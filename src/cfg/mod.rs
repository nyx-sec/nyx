//! Intra-procedural control-flow graph construction.
//!
//! Walks tree-sitter ASTs for all ten supported languages and builds a
//! [`Cfg`] (a petgraph `DiGraph<NodeInfo, EdgeKind>`) per function.
//! [`NodeInfo`] carries the statement kind, label classification, callee
//! name, taint and gate metadata. [`EdgeKind`] distinguishes normal flow,
//! true/false branches, and exception edges.
//!
//! `build_cfg` is the main entry point: given a parsed tree and language,
//! it produces a [`FileCfg`] (one [`Cfg`] per function in the file) along
//! with a [`FuncSummaries`] map for pass-1 summary extraction.
//! `export_summaries` converts in-graph [`LocalFuncSummary`] values to
//! the serializable [`crate::summary::FuncSummary`] form.

#![allow(
    clippy::collapsible_if,
    clippy::let_and_return,
    clippy::unnecessary_map_or
)]

use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::prelude::*;
use tracing::{debug, warn};
use tree_sitter::{Node, Tree};

use crate::labels::{
    Cap, DataLabel, Kind, LangAnalysisRules, classify, classify_all, classify_gated_sink, lookup,
};
use crate::summary::FuncSummary;
use crate::symbol::{FuncKey, Lang};
use crate::utils::snippet::truncate_at_char_boundary;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

mod blocks;
mod conditions;
mod decorators;
mod dto;
mod helpers;
mod hierarchy;
mod imports;
mod literals;
mod params;
pub mod safe_fields;
use blocks::{build_begin_rescue, build_switch, build_try};
use helpers::{
    collect_nested_function_nodes, derive_anon_fn_name_from_context, find_classifiable_inner_call,
    first_call_ident_with_span, first_member_label, first_member_text, is_raii_factory,
    is_subscript_kind, root_member_receiver, subscript_components, subscript_lhs_node,
};
// Re-exports so sibling submodules can keep using `super::name` for
// helpers that physically live in `helpers.rs`.
use conditions::{
    build_condition_chain, build_ternary_diamond, classify_ternary_lhs,
    detect_rust_let_match_guard, emit_rust_match_guard_if, find_ternary_rhs_wrapper,
    is_boolean_operator, unwrap_parens,
};
use decorators::{extract_auth_decorators, extract_route_path_captures};
pub(crate) use helpers::{
    collect_idents, collect_idents_with_paths, find_constructor_type_child, first_call_ident,
    has_call_descendant, member_expr_text, root_receiver_text, text_of,
};
use imports::{
    extract_import_bindings, extract_local_import_view, extract_promisify_aliases,
    rust_bare_join_crate_prefix,
};
#[cfg(test)]
use literals::has_sql_placeholders;
use literals::{
    arg0_kind_and_interpolation, call_ident_of, def_use, detect_go_replace_call_sanitizer,
    detect_rust_replace_chain_sanitizer, extract_arg_callees, extract_arg_string_literals,
    extract_arg_uses, extract_const_keyword_arg, extract_const_macro_arg, extract_const_string_arg,
    extract_destination_field_pairs, extract_destination_kwarg_pairs, extract_kwargs,
    extract_literal_rhs, extract_object_arg_property, extract_shell_array_payload_idents,
    find_call_node, find_call_node_deep, find_chained_inner_call, has_keyword_arg,
    has_object_arg_property, has_only_literal_args, has_string_interpolation,
    is_object_create_null_call, is_parameterized_query_call, java_chain_arg0_kind_for_method,
    js_chain_arg0_kind_for_method, js_chain_outer_method_for_inner, ruby_chain_arg0_for_method,
    walk_chain_inner_call_args,
};
use params::{
    compute_container_and_kind, extract_param_meta, inject_framework_param_sources,
    is_configured_terminator,
};

/// Test-only re-export of `extract_param_meta` so the external
/// `tests/typed_extractors_audit.rs` harness can drive the per-param
/// classifier directly without spinning up the full scan pipeline.
/// Projects away the destructured-siblings third tuple slot so the
/// existing tuple-shape assertions in the audit harness keep working;
/// the sibling info is plumbed separately through `BodyMeta`.
pub fn extract_param_meta_for_test<'a>(
    func_node: tree_sitter::Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Vec<(String, Option<crate::ssa::type_facts::TypeKind>)> {
    extract_param_meta(func_node, lang, code)
        .into_iter()
        .map(|(name, ty, _siblings)| (name, ty))
        .collect()
}

/// Test-only re-export that returns the full per-slot tuple including
/// destructured sibling names.  Used by the destructured-arg-probe
/// regression tests in `src/taint/tests.rs` and the params unit tests
/// in `src/cfg/cfg_tests.rs`.
pub fn extract_param_meta_with_destructured_for_test<'a>(
    func_node: tree_sitter::Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Vec<(
    String,
    Option<crate::ssa::type_facts::TypeKind>,
    Vec<String>,
)> {
    extract_param_meta(func_node, lang, code)
}

/// Test-only helper to populate the per-file DTO class map without
/// running `build_cfg`.  Used by the DTO audit harness in
/// `tests/typed_extractors_audit.rs` to verify that
/// `classify_param_type_*` resolves a same-file DTO via the
/// thread-local map.
pub fn populate_dto_classes_for_test(root: tree_sitter::Node<'_>, lang: &str, code: &[u8]) {
    DTO_CLASSES.with(|cell| {
        *cell.borrow_mut() = dto::collect_dto_classes(root, lang, code);
    });
}

/// Test-only counterpart to [`populate_dto_classes_for_test`].  Always
/// call this at the end of a test that populated the map so per-thread
/// state never leaks into another test.
pub fn clear_dto_classes_for_test() {
    DTO_CLASSES.with(|cell| cell.borrow_mut().clear());
}

// Per-file map of function-node start_byte → DFS preorder index. Stable
// against unrelated edits (inserting a line above a function doesn't
// change its index). Thread-local is safe, `build_cfg` is not
// re-entrant within a single rayon worker.
thread_local! {
    static FN_DFS_INDICES: RefCell<HashMap<usize, u32>> = RefCell::new(HashMap::new());
    /// Per-file DTO class definitions, populated at the top of
    /// [`build_cfg`] so per-parameter classifiers can resolve typed
    /// extractors against same-file DTOs.
    pub(crate) static DTO_CLASSES: RefCell<HashMap<String, crate::ssa::type_facts::DtoFields>>
        = RefCell::new(HashMap::new());
    /// Per-file set of TS / JS `type X = Map<...>` (or `Set<...>` /
    /// `Array<...>` / `T[]`) aliases, populated at the top of
    /// [`build_cfg`].  Lets `classify_param_type_ts` resolve a
    /// parameter typed `m: ElementsMap` to
    /// [`crate::ssa::type_facts::TypeKind::LocalCollection`] via
    /// same-file alias lookup.  Cross-file aliases are not yet
    /// resolved.
    pub(crate) static TYPE_ALIAS_LC: RefCell<std::collections::HashSet<String>>
        = RefCell::new(std::collections::HashSet::new());
    /// Per-file map of `(enclosing-function start_byte, local-variable
    /// name)` → [`crate::ssa::type_facts::TypeKind`].  Populated at the
    /// top of [`build_cfg`] by walking each function body for local
    /// variable declarations whose RHS callee is recognised by
    /// [`crate::ssa::type_facts::constructor_type`].  Consulted by
    /// `find_classifiable_inner_call` (in `helpers.rs`) to rewrite the
    /// receiver in a chained inner call (`sess.createNativeQuery(...)`)
    /// to its type prefix (`HibernateSession.createNativeQuery`) so a
    /// type-qualified label rule fires when the legacy literal-receiver
    /// rule misses.  Java-only today; extends to any language whose
    /// `constructor_type` arm fires on the RHS callee.
    pub(crate) static LOCAL_RECEIVER_TYPES:
        RefCell<HashMap<(usize, String), crate::ssa::type_facts::TypeKind>>
        = RefCell::new(HashMap::new());
}

/// Walk every function-kind node in the tree.  Within each function
/// body, scan non-nested local variable declarations whose RHS is a
/// call expression and whose callee is recognised by
/// [`crate::ssa::type_facts::constructor_type`].  Record
/// `(fn_start, var_name) → TypeKind` so chained inner calls receive a
/// type-qualified rewrite at classify time.
fn populate_local_receiver_types(tree: &Tree, lang: &str, code: &[u8]) {
    use crate::ssa::type_facts::TypeKind;
    let Some(lang_enum) = Lang::from_slug(lang) else {
        return;
    };
    let mut out: HashMap<(usize, String), TypeKind> = HashMap::new();
    walk_functions_for_locals(tree.root_node(), lang, lang_enum, code, &mut out);
    LOCAL_RECEIVER_TYPES.with(|cell| *cell.borrow_mut() = out);
}

fn walk_functions_for_locals(
    root: Node<'_>,
    lang: &str,
    lang_enum: Lang,
    code: &[u8],
    out: &mut HashMap<(usize, String), crate::ssa::type_facts::TypeKind>,
) {
    if lookup(lang, root.kind()) == Kind::Function {
        let fn_start = root.start_byte();
        collect_locals_in_fn(root, fn_start, true, lang, lang_enum, code, out);
    }
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        walk_functions_for_locals(child, lang, lang_enum, code, out);
    }
}

fn collect_locals_in_fn(
    node: Node<'_>,
    fn_start: usize,
    is_root: bool,
    lang: &str,
    lang_enum: Lang,
    code: &[u8],
    out: &mut HashMap<(usize, String), crate::ssa::type_facts::TypeKind>,
) {
    use crate::ssa::type_facts::constructor_type;
    // Don't descend into nested function bodies — they own their own
    // scope and get their own (fn_start, var_name) bindings via the
    // outer walk.
    if !is_root && lookup(lang, node.kind()) == Kind::Function {
        return;
    }
    if node.kind() == "local_variable_declaration"
        || node.kind() == "variable_declarator"
        || node.kind() == "let_declaration"
        || node.kind() == "short_var_declaration"
        || node.kind() == "var_spec"
    {
        let mut cursor = node.walk();
        for declarator in node.children(&mut cursor) {
            if declarator.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(name) = text_of(name_node, code) else {
                continue;
            };
            let Some(value_node) = declarator
                .child_by_field_name("value")
                .or_else(|| declarator.child_by_field_name("right"))
            else {
                continue;
            };
            // The RHS may be a chain like `sf.openSession()`; we want
            // the callee text to feed `constructor_type`.  For
            // method_invocation / call_expression nodes, build the
            // dotted callee path.
            let Some(callee) = callee_text_for_constructor(value_node, lang, code) else {
                continue;
            };
            if let Some(kind) = constructor_type(lang_enum, &callee) {
                out.insert((fn_start, name), kind);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_locals_in_fn(child, fn_start, false, lang, lang_enum, code, out);
    }
}

fn callee_text_for_constructor(node: Node<'_>, lang: &str, code: &[u8]) -> Option<String> {
    match lookup(lang, node.kind()) {
        Kind::CallFn => node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("name"))
            .and_then(|f| text_of(f, code)),
        Kind::CallMethod => {
            let method = node
                .child_by_field_name("method")
                .or_else(|| node.child_by_field_name("name"))
                .and_then(|f| text_of(f, code))?;
            let recv = node
                .child_by_field_name("object")
                .or_else(|| node.child_by_field_name("receiver"))
                .or_else(|| node.child_by_field_name("scope"))
                .and_then(|f| root_receiver_text(f, lang, code));
            match recv {
                Some(r) => Some(format!("{r}.{method}")),
                None => Some(method),
            }
        }
        _ => None,
    }
}

/// Walk up from `n` to find the enclosing function-kind node's
/// `start_byte`.  Returns `None` for top-level nodes.
fn enclosing_fn_start(n: Node<'_>, lang: &str) -> Option<usize> {
    let mut cur = n.parent()?;
    loop {
        if lookup(lang, cur.kind()) == Kind::Function {
            return Some(cur.start_byte());
        }
        cur = cur.parent()?;
    }
}

/// Look up `(fn_start, var_name)` in the per-file local-receiver-types
/// map populated by [`populate_local_receiver_types`].  Returns `None`
/// when no binding was recorded (no view published, name not bound, or
/// RHS callee not recognised by `constructor_type`).
pub(crate) fn lookup_local_receiver_type(
    fn_start: usize,
    var_name: &str,
) -> Option<crate::ssa::type_facts::TypeKind> {
    LOCAL_RECEIVER_TYPES.with(|cell| {
        cell.borrow()
            .get(&(fn_start, var_name.to_string()))
            .cloned()
    })
}

/// Public entry consulted by `find_classifiable_inner_call`: given the
/// inner call's AST node and its bare receiver text, return the
/// `label_prefix()` for the receiver's locally-bound TypeKind, when
/// available.  Returns `None` when no enclosing function is found, no
/// binding was recorded, or the bound `TypeKind` has no label prefix.
pub(crate) fn local_receiver_type_prefix(
    inner_call: Node<'_>,
    receiver: &str,
    lang: &str,
) -> Option<&'static str> {
    let fn_start = enclosing_fn_start(inner_call, lang)?;
    let kind = lookup_local_receiver_type(fn_start, receiver)?;
    kind.label_prefix()
}

/// Populate the per-file DFS-index map from a preorder walk of the
/// tree-sitter AST.  Every node classifying as `Kind::Function` gets
/// a monotonically increasing `u32` starting at 0.
fn populate_fn_dfs_indices(tree: &Tree, lang: &str) {
    fn walk(n: Node, lang: &str, counter: &mut u32, map: &mut HashMap<usize, u32>) {
        if lookup(lang, n.kind()) == Kind::Function {
            map.insert(n.start_byte(), *counter);
            *counter += 1;
        }
        let mut c = n.walk();
        for child in n.children(&mut c) {
            walk(child, lang, counter, map);
        }
    }
    let mut map = HashMap::new();
    let mut counter: u32 = 0;
    walk(tree.root_node(), lang, &mut counter, &mut map);
    FN_DFS_INDICES.with(|cell| *cell.borrow_mut() = map);
}

/// Clear the per-file DFS-index map.  Called at the end of `build_cfg`
/// to avoid leaking state between files on the same thread.
fn clear_fn_dfs_indices() {
    FN_DFS_INDICES.with(|cell| cell.borrow_mut().clear());
}

/// Lookup a function node's DFS index by its `start_byte`.
fn fn_dfs_index(start_byte: usize) -> Option<u32> {
    FN_DFS_INDICES.with(|cell| cell.borrow().get(&start_byte).copied())
}

/// Synthetic name for an anonymous function: `<anon#N>` from the DFS
/// index when available, `<anon@OFFSET>` as fallback.
pub(crate) fn anon_fn_name(start_byte: usize) -> String {
    match fn_dfs_index(start_byte) {
        Some(idx) => format!("<anon#{idx}>"),
        None => format!("<anon@{start_byte}>"),
    }
}

/// True for any anonymous-function synthesis prefix.
pub(crate) fn is_anon_fn_name(name: &str) -> bool {
    name.starts_with("<anon#") || name.starts_with("<anon@")
}

/// -------------------------------------------------------------------------
///  Public AST‑to‑CFG data structures
/// -------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum StmtKind {
    Entry,
    Exit,
    #[default]
    Seq,
    If,
    Loop,
    Break,
    Continue,
    Return,
    Throw,
    Call,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Seq,       // ordinary fall‑through
    True,      // `cond == true` branch
    False,     // `cond == false` branch
    Back,      // back‑edge that closes a loop
    Exception, // from call/throw inside try body → catch entry
}

/// Maximum number of identifiers to store from a condition expression.
pub(super) const MAX_COND_VARS: usize = 8;
pub(super) const MAX_CONDITION_TEXT_LEN: usize = 256;

/// Binary operator extracted from the AST.
///
/// Only set when the SSA assignment maps one-to-one to a single
/// binary expression. Left `None` for nested, compound, or boolean
/// expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    LeftShift,
    RightShift,
    // Comparison
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

/// Call-related metadata for CFG nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallMeta {
    pub callee: Option<String>,
    /// Original textual callee path (e.g. `"c.mu.Lock"`) preserved for legacy
    /// consumers when SSA lowering decomposes a chained-receiver call into a
    /// `FieldProj` chain plus a bare-method `Call`.
    ///
    /// CFG construction does NOT populate this field today (callee already
    /// carries the full path). It is the canonical place to read the original
    /// textual callee for **debug/display only**, analysis code should walk
    /// SSA `FieldProj` receivers or use the
    /// [`crate::labels::bare_method_name`] textual fallback.
    #[doc(hidden)]
    #[serde(default)]
    pub callee_text: Option<String>,
    /// When `find_classifiable_inner_call` overrides the primary callee
    /// (e.g. `parts.add(req.getParameter("input"))` → callee becomes
    /// "req.getParameter"), this field preserves the original outer callee
    /// ("parts.add") so container propagation can still recognise it.
    pub outer_callee: Option<String>,
    /// Byte span of the inner call that supplied the classification, when
    /// `find_classifiable_inner_call` overrode the outer callee.  `None` when
    /// the classification came from the outer AST node directly, in that
    /// case `AstMeta.span` already points at the classified expression.
    ///
    /// Consumers that want the location of the *labeled* call (sink/source/
    /// sanitizer display, flow-step rendering, taint origin attribution)
    /// should use [`NodeInfo::classification_span`] rather than reading this
    /// field directly.  `AstMeta.span` remains the authoritative "whole
    /// statement" span, used by structural passes (unreachability,
    /// resource lifecycle, guard byte scans, CFG/taint span dedup).
    #[serde(default)]
    pub callee_span: Option<(usize, usize)>,
    /// Per-function call ordinal (0-based, only meaningful for Call nodes).
    pub call_ordinal: u32,
    /// Per-argument identifiers for Call nodes. Each inner Vec holds the
    /// identifiers from one argument expression, in parameter-position order.
    /// Empty for non-call nodes or when argument boundaries can't be determined.
    pub arg_uses: Vec<Vec<String>>,
    /// For `CallMethod` nodes: the receiver identifier (e.g. `tainted` in
    /// `tainted.foo()`).  `None` for non-method calls or complex receivers
    /// (member expressions, call expressions, etc.).
    pub receiver: Option<String>,
    /// For gated sinks: which argument positions carry the tainted payload.
    /// When `Some`, only variables from these `arg_uses` positions are checked
    /// for taint.  `None` = all arguments are payload (default).
    pub sink_payload_args: Option<Vec<usize>>,
    /// Keyword/named arguments attached to this call, in source order.
    ///
    /// Each entry is `(keyword_name, uses)` where `uses` are the identifier
    /// references from the keyword's value expression (same shape as an entry
    /// in `arg_uses`).  Populated for languages that expose named arguments
    /// at the call site (e.g. Python `func(shell=True)`, Ruby hash-arg style).
    /// Empty for languages without named arguments and for calls that use
    /// only positional arguments.
    pub kwargs: Vec<(String, Vec<String>)>,
    /// String-literal value at each positional argument of this call, parallel
    /// to `arg_uses`, `Some(s)` when the argument is a syntactic string
    /// literal, `None` otherwise.  Empty for non-call nodes or when positional
    /// boundaries can't be determined.  Consumed by the static-map abstract
    /// analysis (and future literal-aware passes) so they don't need the
    /// source bytes.
    pub arg_string_literals: Vec<Option<String>>,
    /// Destination-aware sink filter for outbound-HTTP gates.
    ///
    /// When `Some(names)`, the SSA sink scan restricts taint checks to
    /// identifiers whose `var_name` matches one of `names`.  Populated by
    /// gated sinks whose activation is [`crate::labels::GateActivation::Destination`]
    /// with `object_destination_fields` set and whose positional destination
    /// arg is an object literal: CFG walks the object literal, collects
    /// identifiers from the named destination fields (url, host, path, …),
    /// and stores them here so `fetch({url: taintedUrl, body: fixed})` fires
    /// while `fetch({url: fixed, body: taintedData})` does not.
    ///
    /// Takes priority over `sink_payload_args` in the SSA sink scan: when a
    /// call has an object-literal destination arg, only idents under the
    /// listed fields may contribute sink findings, not every ident in the
    /// positional slot.
    ///
    /// Legacy single-gate path: populated only when this call site matched
    /// exactly one gate.  When a callee carries multiple gates (e.g. `fetch`
    /// is both an SSRF and a `DATA_EXFIL` gate), per-gate filters live in
    /// [`Self::gate_filters`] and this field is left `None`.
    #[serde(default)]
    pub destination_uses: Option<Vec<String>>,
    /// Per-gate filters for callees that carry multiple gated-sink rules.
    ///
    /// Each entry preserves one matching gate's `(label_caps, payload_args,
    /// destination_uses)` so the SSA sink scan can attribute findings
    /// per-cap.  Empty when the call site matches zero or exactly one gate
    /// (the single-gate case continues to use [`Self::sink_payload_args`] +
    /// [`Self::destination_uses`]).
    #[serde(default)]
    pub gate_filters: Vec<GateFilter>,
    /// True when this call expression is a constructor invocation
    /// (e.g. JS/TS `new Stripe(key)`, PHP `new PDO(...)`).  The SSA Call
    /// transfer uses this to narrow the constructed value's caps: a wrapper
    /// object instance is structurally not a path string, format string,
    /// URL component, or JSON input, so out-of-process side-effect bits
    /// (FILE_IO, FMT_STRING, URL_ENCODE, JSON_PARSE) on the arguments
    /// must not survive into the constructed object.
    #[serde(default)]
    pub is_constructor: bool,
    /// True when this call is `Object.create(null)` (or alias). The returned
    /// value has no prototype chain.  Consumed by TypeFacts to tag the
    /// SsaValue with [`crate::ssa::type_facts::TypeKind::NullPrototypeObject`]
    /// so PROTOTYPE_POLLUTION suppression can fire flow-sensitively at the
    /// synthetic `__index_set__` sink.  Set during CFG node construction so
    /// SSA does not need to re-walk the AST.
    #[serde(default)]
    pub produces_null_proto: bool,
}

/// One gate's contribution at a call site whose callee matches multiple
/// gates.  The SSA taint engine processes each filter independently so a
/// `fetch({url: tainted}, {body: tainted})` flow surfaces as one SSRF
/// finding (URL filter) plus one `DATA_EXFIL` finding (body filter), each
/// carrying its own cap mask rather than a conflated union.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GateFilter {
    /// Sink caps emitted by this gate (e.g. `Cap::SSRF`, `Cap::DATA_EXFIL`).
    pub label_caps: crate::labels::Cap,
    /// Argument positions that carry the tainted payload for this gate.
    pub payload_args: Vec<usize>,
    /// Destination-aware filter: when `Some(names)`, the sink check only
    /// considers SSA values whose `var_name` matches one of `names` (object-
    /// literal destination fields lifted at CFG time).  `None` ⇒ whole arg.
    pub destination_uses: Option<Vec<String>>,
    /// Parallel to [`Self::destination_uses`]: for each entry, the
    /// destination object-literal field name (e.g. `"body"`, `"headers"`,
    /// `"json"`) where the corresponding ident was bound.  Empty when
    /// `destination_uses` is `None` or the gate had no
    /// `object_destination_fields` configured.  Consumed by diag rendering
    /// to embed the destination field in `DATA_EXFIL` messages and SARIF
    /// `properties.data_exfil_field`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_fields: Vec<String>,
}

/// Taint-classification and variable-flow metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaintMeta {
    pub labels: SmallVec<[DataLabel; 2]>, // taint classifications (multi-label)
    /// Raw text of a constant/literal RHS when this node defines a variable
    /// from a syntactic literal with no uses. Used by SSA constant propagation.
    pub const_text: Option<String>,
    pub defines: Option<String>, // variable written by this stmt
    pub uses: Vec<String>,       // variables read
    /// Additional variable definitions from destructuring patterns.
    /// E.g. `const { a, b, c } = source()` → defines="a", extra_defines=["b", "c"].
    pub extra_defines: Vec<String>,
    /// Pattern-position indices for array-pattern destructure bindings.
    /// When non-empty, `array_pattern_indices[0]` is the position index for
    /// `defines`, and `array_pattern_indices[1..]` are the indices for each
    /// element of `extra_defines` in order. Populated only when the LHS is
    /// an `array_pattern` (or tuple_pattern) so consumers can map binding
    /// positions back to source-order arguments — e.g. `const [, b] =
    /// Promise.all([safe, tainted])` records `array_pattern_indices=[1]`
    /// so the SSA destructure-promise rewrite picks index 1 (tainted)
    /// instead of index 0 (safe). Empty for object-destructure, plain
    /// single-binding assignments, and non-array patterns.
    #[serde(default, skip_serializing_if = "SmallVec::is_empty")]
    pub array_pattern_indices: SmallVec<[usize; 4]>,
    /// Source-order RHS array-literal slots for destructure assignments.
    /// Populated only when the LHS is a destructure pattern (`array_pattern`,
    /// `tuple_pattern`, `pattern_list`, `left_assignment_list`) AND the RHS
    /// is an array-literal shape (JS/TS `array`, Python `list`/`tuple`/
    /// `expression_list`, Ruby `array`, Rust `tuple_expression`). Each slot
    /// carries one of: a bare identifier (`Ident`), a syntactic literal
    /// (`Literal`), or a complex expression with its inner identifier uses
    /// (`Complex`). Empty when the RHS shape doesn't match OR a slot is
    /// unrepresentable (spread / list splat) — callers fall back to the
    /// existing scalar-union behavior in that case.
    ///
    /// Used by the SSA destructure rewrite in `lower.rs` so each binding sees
    /// only its index's element instead of the scalar union of every ident on
    /// the RHS. Closes FPs like `const [a, b] = [safe, tainted]; exec(b);`
    /// (Ident shape) as well as `const [c, d] = [fn(req.x), 'lit']; exec(d);`
    /// (Complex shape) where the legacy union painted `d` with `req.x`.
    #[serde(default, skip_serializing_if = "SmallVec::is_empty")]
    pub rhs_array_elements: SmallVec<[RhsArraySlot; 4]>,
}

/// Source-order slot for an RHS array-literal element in a destructure
/// assignment. See [`TaintMeta::rhs_array_elements`] for context.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RhsArraySlot {
    /// Bare identifier (`safe`, `$user`, `req`). The SSA lowering looks up
    /// the reaching def via `var_stacks` and emits an `Assign` of that value.
    Ident(String),
    /// Syntactic literal (string, number, bool, null/nil/None). The SSA
    /// lowering emits a `Const(None)` so the binding carries no taint.
    Literal,
    /// Complex expression (call, binary, subscript, member access, nested
    /// array literal). Carries the inner identifier uses harvested from the
    /// slot's subtree plus a per-slot `source_cap` recognised by classifying
    /// the slot's own subtree (via `first_member_label`).
    ///
    /// When `source_cap` is non-empty the SSA lowering knows the source
    /// pattern lives in THIS slot and emits `SsaOp::Source` for the binding.
    /// Sibling Complex slots whose `source_cap` is empty fall through to the
    /// slot-scoped `Assign(inner reaching defs)` path, so a safe Complex
    /// sibling stops inheriting the outer node's Source label.
    Complex {
        uses: SmallVec<[String; 4]>,
        #[serde(default, skip_serializing_if = "crate::labels::Cap::is_empty")]
        source_cap: crate::labels::Cap,
    },
}

/// AST origin/location metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AstMeta {
    pub span: (usize, usize), // byte offsets in the original file
    /// Name of the enclosing function (set during CFG construction).
    pub enclosing_func: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeInfo {
    pub kind: StmtKind,
    pub call: CallMeta,
    pub taint: TaintMeta,
    pub ast: AstMeta,
    /// For If nodes: raw condition text (truncated to 256 chars). None for non-If nodes.
    pub condition_text: Option<String>,
    /// For If nodes: identifiers referenced in the condition (sorted, deduped, max 8).
    pub condition_vars: Vec<String>,
    /// For If nodes: whether the condition has a leading negation (`!` / `not`).
    pub condition_negated: bool,
    /// True when this is a Call node whose argument list contains only
    /// syntactic literal values (strings, numbers, booleans, null/nil,
    /// arrays/lists/tuples of literals). Also true for zero-argument calls
    /// (no argument-carried taint vector).
    ///
    /// This flag is scoped to taint-style sink suppression: it indicates
    /// that no attacker-controlled data enters through the immediate
    /// arguments. It does NOT mean the call is "safe" in general, other
    /// detectors (resource lifecycle, structural analysis) may still
    /// legitimately flag these calls.
    pub all_args_literal: bool,
    /// True for synthetic catch-parameter nodes injected at catch clause entry.
    /// The taint transfer function uses this to conservatively taint the
    /// caught exception variable.
    pub catch_param: bool,
    /// For Call nodes: the callee name of the call expression wrapping each
    /// argument (per-position, matching arg_uses). For Assignment sink nodes:
    /// the RHS call callee at position 0 (if the RHS is a call expression).
    /// Used by SSA sink detection for interprocedural sanitizer resolution.
    pub arg_callees: Vec<Option<String>>,
    /// For cast/type-assertion expressions: the target type name extracted
    /// from the AST.  E.g. `(String) x` → `"String"`, `x as number` → `"number"`,
    /// `x.(io.Reader)` → `"io.Reader"`.  Used by type-flow constraint solving
    /// to refine the type environment at the SSA level.
    pub cast_target_type: Option<String>,
    /// Arithmetic operator for binary expression assignments.
    /// Only set when the CFG node is a single binary expression with a
    /// clear one-to-one operator mapping. `None` for nested, compound,
    /// boolean, or ambiguous expressions.
    pub bin_op: Option<BinOp>,
    /// Parsed literal operand from a binary expression.
    /// When `bin_op` is set and one operand is a numeric literal (the other
    /// being an identifier captured in `uses`), this holds the parsed value.
    /// Enables abstract-domain transfer even when the SSA instruction has
    /// only one use (the literal isn't an identifier and isn't in `uses`).
    pub bin_op_const: Option<i64>,
    /// True when this acquisition node is inside a language-managed cleanup
    /// scope (Python `with`, Java try-with-resources, C# `using`).
    /// Only meaningful on Call nodes that define a resource variable.
    /// Leak detectors check this flag on the acquire site, not the variable.
    pub managed_resource: bool,
    /// True when this Call node is a deferred release (Go `defer f.Close()`).
    /// Deferred releases are not processed as immediate closes; instead they
    /// suppress leak findings (defer guarantees cleanup at function exit).
    /// Only set on Call nodes, not on all nodes within a defer_statement.
    pub in_defer: bool,
    /// True when this is a SQL_QUERY sink whose first argument is a string
    /// literal containing parameterized-query placeholders (`$1`, `?`, `%s`,
    /// `:name`) AND the call has >= 2 arguments (the params array/tuple).
    /// Both CFG analysis and SSA taint suppress findings on such nodes.
    pub parameterized_query: bool,
    /// Constant leading string prefix recovered from the node's RHS when it
    /// is a template literal (JS/TS) with a leading `string_fragment` or an
    /// equivalent constant-string-then-interpolation shape.  Populated for
    /// assignment-like nodes (`variable_declarator`, `assignment_expression`,
    /// `lexical_declaration`).  Consumed by the abstract string domain in
    /// `transfer_abstract` to seed a `StringFact::from_prefix` on the result
    /// SSA value so SSRF prefix-suppression can fire for values constructed
    /// from template literals.
    pub string_prefix: Option<String>,
    /// True when this node is a binary equality/inequality expression whose
    /// operator is `==` / `!=` / `===` / `!==` and exactly one operand is a
    /// syntactic literal (string / number / null / boolean). The SSA taint
    /// transfer uses this to suppress boolean-result taint propagation: the
    /// boolean outcome of `x === 'literal'` carries no attacker-controlled
    /// data, so downstream branches on it should not inherit x's caps.
    pub is_eq_with_const: bool,
    /// True when this node reads a numeric-length property on a container:
    /// `arr.length`, `map.size`, `buf.byteLength`, `items.count`, `vec.len()`
    ///, either as a pure property access or as a zero-arg method call.
    /// Populated by inspecting the AST in `push_node` across JS/TS, Python,
    /// Ruby, Java, Rust, PHP, and C/C++ idioms where these accessors return
    /// an integer.  Consumed by the type-fact analysis (`ssa::type_facts`)
    /// to infer `TypeKind::Int`, which drives HTML_ESCAPE / SQL_QUERY /
    /// FILE_IO / SHELL_ESCAPE sink suppression for provably numeric
    /// payloads.
    pub is_numeric_length_access: bool,
    /// the field name read on the RHS of an assignment whose
    /// RHS is a single member-access expression (e.g. `let x = dto.email`).
    /// Set to `Some("email")` for that shape; left `None` otherwise.
    /// Consumed by the type-fact analysis (`ssa::type_facts`) so reads
    /// against a [`crate::ssa::type_facts::TypeKind::Dto`] receiver pick
    /// up the field's declared `TypeKind`.  Strictly additive, when
    /// `None`, the legacy copy-prop semantics apply.
    pub member_field: Option<String>,
    /// True when this assignment / declaration's RHS is a function or
    /// lambda literal (`obj.handler = (e) => {...}`, `let f = function(){}`).
    /// State analysis uses this to suppress resource-ownership transfer:
    /// storing a function reference into a property does not move the
    /// resources captured by the closure body, so the lifecycle of those
    /// captures must remain unchanged on the assignment node.
    pub rhs_is_function_literal: bool,
    /// True when this CFG node was produced from a tree-sitter
    /// `await_expression` (JS/TS `Kind::AwaitForward`).  The SSA lowering
    /// emits `SsaOp::Assign(operand)` for such nodes so taint, origins,
    /// and abstract-domain facts forward 1:1 across the await boundary.
    /// Strictly additive: when `false`, legacy lowering applies.
    #[serde(default)]
    pub is_await_forward: bool,
}

impl NodeInfo {
    /// Byte span of the *labeled* sub-expression in this CFG node.
    ///
    /// When `find_classifiable_inner_call` found the source/sink/sanitizer
    /// deep inside an enclosing statement (e.g. `escapeHtml(...)` buried in
    /// a template literal whose outer node is the `overlay.innerHTML = ...`
    /// assignment), `call.callee_span` pinpoints the inner call; otherwise
    /// the whole node's span is the classification span.
    ///
    /// Use this for **display and source-attribution**: taint finding sink
    /// lines, flow-step rendering, symbolic witness extraction, debug views.
    ///
    /// Use `ast.span` directly for **structural grain**: unreachability,
    /// resource lifecycle, guard byte scans, CFG/taint span dedup, anywhere
    /// the enclosing statement is the meaningful unit.
    #[inline]
    pub fn classification_span(&self) -> (usize, usize) {
        self.call.callee_span.unwrap_or(self.ast.span)
    }
}

/// Intra‑file function summary with graph‑local node indices.
///
/// Keeps all three cap dimensions independently so that a function that is
/// *both* a source and a sink (e.g. reads env then shells out) does not
/// lose information.
#[derive(Debug, Clone)]
pub struct LocalFuncSummary {
    #[allow(dead_code)] // used for future intra-file graph traversal
    pub entry: NodeIndex,
    #[allow(dead_code)] // used for future intra-file graph traversal
    pub exit: NodeIndex,
    pub source_caps: Cap,
    pub sanitizer_caps: Cap,
    pub sink_caps: Cap,
    pub param_count: usize,
    pub param_names: Vec<String>,
    /// Which parameter indices (0‑based) flow through to the return value.
    pub propagating_params: Vec<usize>,
    /// Which parameter indices flow to internal sinks.
    pub tainted_sink_params: Vec<usize>,
    /// Per-call-site metadata for every call inside this function body.
    /// Each entry carries the callee's raw name plus arity, receiver,
    /// qualifier, and ordinal so callers can resolve overloads and
    /// method-call targets without re-parsing.
    pub callees: Vec<crate::summary::CalleeSite>,
    /// Identity discriminator: enclosing container path, `""` for free
    /// top-level functions.  Copied into `FuncSummary.container` at export.
    pub container: String,
    /// Identity discriminator: byte offset / occurrence index for disambiguating
    /// same-name siblings (closures, duplicate defs).
    pub disambig: Option<u32>,
    /// Structural role of this definition.
    pub kind: crate::symbol::FuncKind,
}

pub type Cfg = Graph<NodeInfo, EdgeKind>;
pub type FuncSummaries = HashMap<FuncKey, LocalFuncSummary>;

// -------------------------------------------------------------------------
// Per-body CFG types
// -------------------------------------------------------------------------

/// Opaque identifier for an executable body within a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BodyId(pub u32);

/// Identifies the kind of executable body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    TopLevel,
    NamedFunction,
    AnonymousFunction,
}

/// Metadata for a single executable body.
#[derive(Debug, Clone)]
pub struct BodyMeta {
    pub id: BodyId,
    pub kind: BodyKind,
    pub name: Option<String>,
    pub params: Vec<String>,
    /// Per-parameter [`crate::ssa::type_facts::TypeKind`] inferred from
    /// decorators / annotations / static type text at CFG construction
    /// time.  Same length as `params`; positions with no recoverable
    /// type info are `None`.  Strictly additive, when every entry is
    /// `None`, downstream behaviour is identical to the type-unaware path.
    pub param_types: Vec<Option<crate::ssa::type_facts::TypeKind>>,
    /// Per-parameter destructured-binding sibling names.  Same length
    /// as `params`; entry `i` lists field names bound by the same
    /// argument slot as `params[i]`, excluding the primary name itself.
    /// Empty for non-destructured params.  Today populated only for
    /// JS/TS object-pattern formals (`({ a, b, c })` → params=["a"],
    /// destructured=[["b","c"]]).  Used by per-parameter taint-summary
    /// probing in `extract_ssa_func_summary` so destructured bindings
    /// inside the body share the slot's seeded caps and any of them
    /// being in `validated_must` at a return path counts as the slot
    /// being validated.  Closes the residual gap behind CVE-2026-25544.
    pub param_destructured_fields: Vec<Vec<String>>,
    pub param_count: usize,
    pub span: (usize, usize),
    pub parent_body_id: Option<BodyId>,
    /// Canonical identity for this body.
    ///
    /// `Some(..)` for named/anonymous function bodies, carrying the same
    /// `FuncKey` under which `FileCfg::summaries` stores its
    /// `LocalFuncSummary`.  `None` for the synthetic top-level body.
    ///
    /// All intra-file maps keyed on function identity (SSA summaries, callee
    /// bodies, inline cache, callback bindings) use this key, never the bare
    /// leaf `name`, which is collision-prone across (container, arity,
    /// disambig, kind).
    pub func_key: Option<FuncKey>,
    /// Normalized auth-decorator/annotation/attribute names attached to this
    /// function (Python `@login_required`, Java `@PreAuthorize`, Ruby class
    /// `before_action :authenticate_user!`, etc.). Lowercased, bare names
    /// without `@`, `#[..]`, `[[..]]` wrappers or argument tails. The state
    /// machine consumes this to seed the entry `AuthLevel` for privileged-sink
    /// checks. Empty for top-level and for functions without auth markers.
    pub auth_decorators: Vec<String>,
    /// Per-formal route-capture flag. Same length as `params`. `true` at
    /// position `i` iff the formal name appears as a path capture in a
    /// framework routing decorator on this function (Flask
    /// `@app.route("/users/<name>")`, blueprint-prefixed `@bp.get("/u/<int:id>")`,
    /// FastAPI / Starlette verb decorators). Today populated only for Python.
    /// The entry-kind seeding pass consults this for `FlaskRoute` so only
    /// path-bound formals (not implicit globals or DI handles) are painted
    /// as adversary input. Empty for top-level and for functions without
    /// matching decorators.
    pub param_route_capture: Vec<bool>,
}

/// A single executable body's CFG plus metadata.
#[derive(Debug)]
pub struct BodyCfg {
    pub meta: BodyMeta,
    pub graph: Cfg,
    pub entry: NodeIndex,
    pub exit: NodeIndex,
}

/// A single import alias binding: local alias → original exported name + module.
#[derive(Debug, Clone)]
pub struct ImportBinding {
    /// The original exported symbol name (e.g. `getInput`).
    pub original: String,
    /// The module path (e.g. `./source`), if extractable.
    pub module_path: Option<String>,
}

/// Per-file map from locally-bound alias name to its import origin.
/// Populated during CFG construction for ES6 `import { A as B }` and
/// CommonJS `const { A: B } = require(...)` patterns.
pub type ImportBindings = HashMap<String, ImportBinding>;

/// A single promisify alias binding: local name bound to `util.promisify(X)`
/// carries the labels of its wrapped callee `X`.
#[derive(Debug, Clone)]
pub struct PromisifyAlias {
    /// The wrapped callee's canonical textual name (e.g. `child_process.exec`
    /// or `fs.readFile`).  Used directly for label classification so downstream
    /// sink / source detection treats the alias the same as the original.
    pub wrapped: String,
}

/// Per-file map from local binding name to its promisify wrap origin.
/// Populated for JS/TS files at CFG construction time for patterns like
/// `const alias = util.promisify(wrapped)` or `const alias = promisify(wrapped)`.
pub type PromisifyAliases = HashMap<String, PromisifyAlias>;

/// All CFGs for a file.
#[derive(Debug)]
pub struct FileCfg {
    pub bodies: Vec<BodyCfg>,
    pub summaries: FuncSummaries,
    /// Import alias bindings: local alias → (original name, module path).
    pub import_bindings: ImportBindings,
    /// Promisify wrapper aliases: local name → wrapped callee name.
    /// Only populated for JS/TS files.
    pub promisify_aliases: PromisifyAliases,
    /// per-file class / trait / interface hierarchy edges.
    /// Each entry is `(sub_container, super_container)` after
    /// language-specific normalisation.  See
    /// `crate::cfg::hierarchy` for the per-language extraction
    /// rules and [`crate::callgraph::TypeHierarchyIndex`] for the
    /// downstream consumer.  Empty for languages without an
    /// extractor (Go, C) and for files with no inheritance / impl
    /// declarations.
    pub hierarchy_edges: Vec<(String, String)>,
    /// Phase-04 resolver output: per-file import bindings resolved
    /// against the project [`crate::resolve::ModuleGraph`]. Populated
    /// post-`build_cfg` by `crate::ast::ParsedFile::from_source` when
    /// a [`crate::resolve::ModuleGraph`] is available on the active
    /// `Config`. Empty for non-JS/TS files, scans without a configured
    /// resolver, and unit tests that build a CFG directly.
    pub resolved_imports: Vec<crate::resolve::ImportBinding>,
    /// Phase 10 — Next.js entry-point classification keyed by the
    /// function definition's tree-sitter byte span. Populated for
    /// JS/TS files, empty otherwise. The summary-extraction pipeline
    /// matches against [`BodyMeta::span`] to attach the
    /// [`crate::entry_points::EntryKind`] to the resulting summary.
    pub entry_kinds: std::collections::HashMap<(usize, usize), crate::entry_points::EntryKind>,
    /// Per-file local import view: local-name → source-module specifier.
    /// Built once during JS/TS CFG construction (empty for other langs).
    /// Consumed by gated label rules and by the ORM TypeKind import gate
    /// in `crate::ssa::type_facts::constructor_type` (via the
    /// `FILE_IMPORTS_TLS` thread-local set around per-body SSA passes).
    pub local_imports: HashMap<String, String>,
    /// Class fields whose `.get(...)` lookups are bounded to a finite
    /// set of literal string values.  Populated for Java
    /// `final ... = Map.of(literal, literal, ...)` declarations; empty
    /// for other languages and shapes.  Consumed by the SSA taint
    /// engine's container-Load fallback (via the
    /// `JAVA_SAFE_FIELDS_TLS` thread-local) so a tainted lookup key
    /// does not light up downstream sinks when the receiver is a
    /// known-safe map field.
    pub safe_lookup_fields: HashMap<String, Vec<String>>,
    /// Class-level constant scalars: field name → literal text.
    /// Populated for Java `static final TYPE NAME = LITERAL;` declarations
    /// where the RHS is a primitive scalar literal (string, integer,
    /// floating-point, char, boolean, null).  Consumed by
    /// `cfg_analysis::guards` to recognise sink arguments that resolve to
    /// class-level constants (the per-function SSA const-prop sees a free
    /// identifier and would otherwise treat the binding as runtime-dynamic).
    /// Empty for non-Java files.
    pub class_constant_scalars: HashMap<String, String>,
}

impl FileCfg {
    /// The top-level / module body (always `BodyId(0)`).
    pub fn toplevel(&self) -> &BodyCfg {
        &self.bodies[0]
    }
    /// Look up a body by its `BodyId`.
    pub fn body(&self, id: BodyId) -> &BodyCfg {
        &self.bodies[id.0 as usize]
    }
    /// All non-top-level bodies (functions, closures, callbacks).
    pub fn function_bodies(&self) -> &[BodyCfg] {
        &self.bodies[1..]
    }
    /// The first function body, or top-level if no functions exist.
    /// Useful for tests where source is wrapped in a single function.
    pub fn first_body(&self) -> &BodyCfg {
        if self.bodies.len() > 1 {
            &self.bodies[1]
        } else {
            &self.bodies[0]
        }
    }
    /// Total CFG node count across all bodies.
    pub fn total_node_count(&self) -> usize {
        self.bodies.iter().map(|b| b.graph.node_count()).sum()
    }
}

/// Create a `NodeInfo` with only kind, span, and enclosing_func set.
/// All other fields are empty/default.
fn make_empty_node_info(
    kind: StmtKind,
    span: (usize, usize),
    enclosing_func: Option<&str>,
) -> NodeInfo {
    NodeInfo {
        kind,
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_owned()),
        },
        ..Default::default()
    }
}

/// Create a fresh body-level `Cfg` with synthetic Entry and Exit nodes.
fn create_body_graph(
    span_start: usize,
    span_end: usize,
    enclosing_func: Option<&str>,
) -> (Cfg, NodeIndex, NodeIndex) {
    let mut g: Cfg = Graph::with_capacity(32, 64);
    let entry = g.add_node(make_empty_node_info(
        StmtKind::Entry,
        (span_start, span_start),
        enclosing_func,
    ));
    let exit = g.add_node(make_empty_node_info(
        StmtKind::Exit,
        (span_end, span_end),
        enclosing_func,
    ));
    (g, entry, exit)
}

/// Extract raw condition metadata from an If AST node.
///
/// Returns `(condition_text, condition_vars, condition_negated)`.
/// The condition subtree is located via `child_by_field_name("condition")`
/// for most languages, with a positional fallback for Rust `if_expression`.
///
/// Negation is detected by checking for a leading unary `!` operator or
/// `not` keyword.  Variables are sorted, deduped, and capped at
/// [`MAX_COND_VARS`].
fn extract_condition_raw<'a>(
    ast: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> (Option<String>, Vec<String>, bool) {
    // 1. Find the condition subtree.
    let cond_node = ast.child_by_field_name("condition").or_else(|| {
        // Rust `if_expression` uses positional children: the condition is
        // the first child that is not a keyword, block, or `let` pattern.
        let mut cursor = ast.walk();
        ast.children(&mut cursor).find(|c| {
            let k = c.kind();
            !matches!(lookup(lang, k), Kind::Block | Kind::Trivia)
                && k != "if"
                && k != "else"
                && k != "let"
                && k != "{"
                && k != "}"
                && k != "("
                && k != ")"
        })
    });

    let Some(cond) = cond_node else {
        return (None, Vec::new(), false);
    };

    // 2. Detect leading negation (`!expr`, `not expr`, Ruby `unless`).
    let (inner, negated) = detect_negation(cond, ast, lang);

    // 3. Collect identifiers from the (inner) condition subtree.
    let mut vars = Vec::new();
    collect_idents(inner, code, &mut vars);
    vars.sort();
    vars.dedup();
    vars.truncate(MAX_COND_VARS);

    // 4. Extract text, truncated.  UTF-8-safe, gogs (Gurmukhi) /
    //    discourse (Cyrillic) trip raw byte slices on regex literals.
    let text = text_of(cond, code)
        .map(|t| truncate_at_char_boundary(&t, MAX_CONDITION_TEXT_LEN).to_string());

    (text, vars, negated)
}

/// Detect leading negation and return the inner expression.
///
/// Handles:
/// - `!expr` (unary_expression / prefix_unary_expression with `!` operator)
/// - `not expr` (Python `not_operator`, Ruby)
///
/// NOTE: Ruby `unless` is NOT handled here. The CFG builder already swaps
/// True/False edges for `unless` (cfg.rs lines 2076-2085), so the edge labels
/// encode the correct branch semantics. Setting `condition_negated=true` here
/// would cause a double-negation in `compute_succ_states`, applying validation
/// to the wrong branch.
pub(super) fn detect_negation<'a>(
    cond: Node<'a>,
    _if_ast: Node<'a>,
    _lang: &str,
) -> (Node<'a>, bool) {
    // Unwrap parenthesized_expression, JS/Java/PHP wrap if-conditions in parens.
    // This lets us detect negation inside: `if (!expr)` → cond is `(!expr)`.
    let cond = if cond.kind() == "parenthesized_expression" {
        cond.child_by_field_name("expression")
            .or_else(|| {
                let mut cursor = cond.walk();
                cond.children(&mut cursor)
                    .find(|c| c.kind() != "(" && c.kind() != ")")
            })
            .unwrap_or(cond)
    } else {
        cond
    };

    // `!expr` appears as unary_expression, not_operator, or prefix_unary_expression
    // with a `!` or `not` operator child.  PHP's tree-sitter grammar emits
    // `unary_op_expression` for unary `!` (and `-`/`+`/`~`) — without it,
    // `if (!validate($x))` carries `condition_negated=false` and the
    // True branch is treated as the validated path even though it is the
    // rejection path, leaving downstream sinks unsuppressed.
    let is_negation_wrapper = matches!(
        cond.kind(),
        "unary_expression"
            | "not_operator"
            | "prefix_unary_expression"
            | "unary_not"
            | "unary_op_expression"
    );

    if is_negation_wrapper {
        // Check if the first child is a `!` or `not` operator.
        let has_not = cond
            .child(0)
            .is_some_and(|c| c.kind() == "!" || c.kind() == "not");

        if has_not {
            // Return the operand (inner expression after the `!` / `not`).
            let inner = cond
                .child_by_field_name("argument")
                .or_else(|| cond.child_by_field_name("operand"))
                .or_else(|| {
                    // Last non-operator child.
                    let mut cursor = cond.walk();
                    cond.children(&mut cursor)
                        .filter(|c| c.kind() != "!" && c.kind() != "not")
                        .last()
                })
                .unwrap_or(cond);
            return (inner, true);
        }
    }

    (cond, false)
}

/// Extract a binary operator from an AST node.
///
/// Covers arithmetic, bitwise, and comparison operators. Conservative
/// policy: only returns `Some(BinOp)` when the AST node directly IS a
/// binary expression or is an assignment/expression wrapper containing
/// a single binary expression as its immediate RHS. Returns `None` for
/// nested binary expressions, compound assignments (`+=`), boolean
/// operators (`&&`, `||`), and any ambiguous cases.
/// Phase 12 deferred fix: when the file imports `tokio::join` / `futures::join`
/// (or `_::try_join`) via `use`, rewrite a bare `join` / `try_join` macro
/// callee to its qualified form so the SSA-level promise-combinator
/// recogniser fires. Returns `None` for every non-Rust input and for
/// macro callees that already carry a `::` prefix.
fn rewrite_rust_bare_join_macro(raw: &str, ast: Node, lang: &str, code: &[u8]) -> Option<String> {
    if lang != "rust" || raw.contains("::") {
        return None;
    }
    if !matches!(raw, "join" | "try_join") {
        return None;
    }
    let mut root = ast;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let prefix = rust_bare_join_crate_prefix(root, code, raw)?;
    Some(format!("{prefix}::{raw}"))
}

fn extract_bin_op(ast: Node, lang: &str) -> Option<BinOp> {
    // Find the binary expression node: either ast itself or immediate child.
    let bin_expr = find_single_binary_expr(ast, lang)?;

    // Walk children to find the operator token (anonymous node between operands).
    let mut cursor = bin_expr.walk();
    for child in bin_expr.children(&mut cursor) {
        if child.is_named() {
            continue; // Skip named children (operands)
        }
        let kind = child.kind();
        return match kind {
            "+" => Some(BinOp::Add),
            "-" => Some(BinOp::Sub),
            "*" => Some(BinOp::Mul),
            "/" => Some(BinOp::Div),
            "%" => Some(BinOp::Mod),
            // Bitwise (single-char tokens, no conflict with && / ||)
            "&" => Some(BinOp::BitAnd),
            "|" => Some(BinOp::BitOr),
            "^" => Some(BinOp::BitXor),
            "<<" => Some(BinOp::LeftShift),
            ">>" => Some(BinOp::RightShift),
            // Comparison (=== / !== are JS/TS strict equality)
            "==" | "===" => Some(BinOp::Eq),
            "!=" | "!==" => Some(BinOp::NotEq),
            "<" => Some(BinOp::Lt),
            "<=" => Some(BinOp::LtEq),
            ">" => Some(BinOp::Gt),
            ">=" => Some(BinOp::GtEq),
            _ => None, // Boolean (&&, ||), assignment ops, etc.
        };
    }
    None
}

/// Find the RHS value node of an assignment-like AST node (variable declarator,
/// lexical declaration, assignment expression). Used by helpers that need to
/// inspect what an identifier is being initialized to.
fn assignment_rhs<'a>(ast: Node<'a>) -> Option<Node<'a>> {
    match ast.kind() {
        "variable_declarator" | "assignment_expression" | "assignment" => ast
            .child_by_field_name("value")
            .or_else(|| ast.child_by_field_name("right")),
        // Phase 14 — Java `local_variable_declaration`, Go
        // `short_var_declaration` / `var_spec`, Rust `let_declaration`,
        // Python `assignment` (already covered above), and PHP
        // `assignment_expression` (covered above).  Added here so the
        // `string_prefix` extractor can walk the RHS of a plain
        // declaration in any supported language.
        "variable_declaration"
        | "lexical_declaration"
        | "local_variable_declaration"
        | "short_var_declaration"
        | "var_spec"
        | "var_declaration"
        | "let_declaration" => {
            // Walk direct children for the first variable_declarator with a value.
            let mut w = ast.walk();
            ast.named_children(&mut w)
                .find(|c| c.kind() == "variable_declarator")
                .and_then(|d| {
                    d.child_by_field_name("value")
                        .or_else(|| d.child_by_field_name("right"))
                })
                .or_else(|| {
                    // Go: short_var_declaration's value is on a
                    // `expression_list` field "right".
                    ast.child_by_field_name("right")
                        .or_else(|| ast.child_by_field_name("value"))
                })
                .or_else(|| {
                    // Rust let_declaration: value field directly on the
                    // node (no wrapping declarator).
                    ast.child_by_field_name("value")
                })
        }
        "expression_statement" => {
            // expression_statement wraps an assignment_expression
            let mut w = ast.walk();
            ast.named_children(&mut w).find_map(|c| match c.kind() {
                "assignment_expression" | "assignment" => c
                    .child_by_field_name("right")
                    .or_else(|| c.child_by_field_name("value")),
                _ => None,
            })
        }
        _ => None,
    }
}

/// Extract a constant leading string prefix from an assignment-like node's
/// RHS when the RHS is a JS/TS template literal beginning with a
/// `string_fragment` or a binary `+` expression whose left operand is a string
/// literal. Returns `None` if the grammar does not expose such a shape.
///
/// The recovered prefix is used by the abstract string domain to seed a
/// `StringFact::from_prefix` on the result SSA value. For SSRF detection,
/// when the prefix contains `scheme://host/`, the sink is suppressed because
/// the attacker cannot reach a different host.
fn extract_template_prefix(ast: Node, lang: &str, code: &[u8]) -> Option<String> {
    // Phase 14 — extended beyond JS/TS so the SSRF prefix-lock fires
    // across every supported language whose origin-locked URL shape
    // is a literal+tainted string concatenation.  The grammar
    // dispatch lives in [`prefix_of_expression`]; this function only
    // walks the assignment-RHS / first-call-arg slots that consume
    // the prefix.
    let supported = matches!(
        lang,
        "javascript" | "typescript" | "java" | "go" | "php" | "ruby" | "python" | "rust"
    );
    if !supported {
        return None;
    }

    // Assignment-like node: inspect the RHS directly.
    if let Some(rhs) = assignment_rhs(ast) {
        if let Some(p) = prefix_of_expression(rhs, code) {
            return Some(p);
        }
    }

    // Call expression (including sink call nodes): inspect the first
    // positional argument. Covers `axios.get(\`https://host/…${x}\`)` shape
    // where the template literal is inline at the sink.
    if matches!(
        ast.kind(),
        "call_expression"
            | "call"
            | "new_expression"
            | "object_creation_expression"
            | "method_invocation"
            | "macro_invocation"
            | "function_call_expression"
    ) {
        let args = ast
            .child_by_field_name("arguments")
            .or_else(|| ast.child_by_field_name("argument_list"));
        if let Some(args_node) = args {
            let mut w = args_node.walk();
            if let Some(first) = args_node.named_children(&mut w).next() {
                if let Some(p) = prefix_of_expression(first, code) {
                    return Some(p);
                }
            }
        }
    }

    None
}

/// Return the leading constant string of `node` if it is a template literal or
/// a left-associated `"lit" + x` binary expression. Used by
/// `extract_template_prefix` for both assignment RHS and call arguments.
///
/// Also descends through `await` / `yield` wrappers and into the first
/// argument of a call expression, this covers the common sink shape
/// `await axios.get(\`https://host/…${x}\`)` where the template literal lives
/// inside a call inside an `await` wrapper.
fn prefix_of_expression(node: Node, code: &[u8]) -> Option<String> {
    // Unwrap trivial wrappers (parentheses, TS `as` / type assertions, await/yield).
    let mut cur = node;
    for _ in 0..6 {
        match cur.kind() {
            "parenthesized_expression" => {
                cur = cur.named_child(0)?;
            }
            "as_expression" | "type_assertion" | "satisfies_expression" | "non_null_expression" => {
                cur = cur
                    .child_by_field_name("expression")
                    .or_else(|| cur.named_child(0))?;
            }
            "await_expression" | "yield_expression" => {
                cur = cur.named_child(0)?;
            }
            "call_expression" | "call" | "new_expression" => {
                // Descend into the first positional argument (e.g.
                // `axios.get(\`https://…${x}\`)`, the URL we want to lock
                // is the template-literal first argument of the call).
                let args = cur
                    .child_by_field_name("arguments")
                    .or_else(|| cur.child_by_field_name("argument_list"))?;
                let mut w = args.walk();
                cur = args.named_children(&mut w).next()?;
            }
            _ => break,
        }
    }

    // Case 1: template literal, `\`scheme://host/…${x}…\``.
    if cur.kind() == "template_string" {
        let mut w = cur.walk();
        let first_child = cur.named_children(&mut w).next()?;
        // Leading fragment only counts when the very first piece is a literal
        // text fragment (not an interpolation like `\`${x}…\``).
        if first_child.kind() == "string_fragment" {
            let frag = text_of(first_child, code)?;
            if !frag.is_empty() {
                return Some(frag);
            }
        }
        return None;
    }

    // Case 2: `"scheme://host/" + x` / PHP `"scheme://host/" . $x`,
    // LHS is a string literal.  Phase 14: also accept `.` as the
    // concat operator so PHP's `"prefix" . $tainted` shape locks the
    // SSRF prefix the same way `+`-using languages do.
    if matches!(
        cur.kind(),
        "binary_expression" | "binary_operator" | "binary"
    ) {
        let mut w2 = cur.walk();
        let mut ops = cur.children(&mut w2).filter(|c| !c.is_named());
        if !ops.any(|c| matches!(c.kind(), "+" | ".")) {
            return None;
        }
        let left = cur.named_child(0)?;
        if matches!(
            left.kind(),
            "string"
                | "string_fragment"
                | "string_literal"
                | "interpreted_string_literal"
                | "raw_string_literal"
                | "encapsed_string"
        ) {
            // For strings with embedded fragments (Java string_literal
            // wraps a string_fragment child), recurse one level into
            // the fragment to get the raw text without quote tokens.
            let inner_text = if matches!(left.kind(), "string_literal" | "encapsed_string") {
                let mut iw = left.walk();
                left.named_children(&mut iw)
                    .find(|c| c.kind() == "string_fragment")
                    .and_then(|n| text_of(n, code))
            } else {
                None
            };
            let raw = match inner_text {
                Some(t) => t,
                None => text_of(left, code)?,
            };
            let trimmed = strip_string_quotes_loose(&raw);
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    // Case 3: Rust `format!("scheme://host/{}", x)` macro invocation.
    // The first positional arg is the format string literal whose
    // leading literal text (up to the first `{`) is the locked prefix.
    if cur.kind() == "macro_invocation" {
        let macro_name = cur
            .child_by_field_name("macro")
            .and_then(|n| text_of(n, code))
            .unwrap_or_default();
        if matches!(
            macro_name.as_str(),
            "format" | "write" | "writeln" | "println" | "eprintln" | "print" | "eprint"
        ) {
            // tree-sitter-rust models macro args under a named
            // `token_tree` child rather than via the `arguments` field.
            // Walk every direct child looking for the first string
            // literal — that's the format-string positional arg.
            let mut iw = cur.walk();
            let mut first_string: Option<Node> = None;
            for child in cur.named_children(&mut iw) {
                if matches!(child.kind(), "string_literal" | "raw_string_literal") {
                    first_string = Some(child);
                    break;
                }
                if child.kind() == "token_tree" {
                    let mut ttw = child.walk();
                    for inner in child.named_children(&mut ttw) {
                        if matches!(inner.kind(), "string_literal" | "raw_string_literal") {
                            first_string = Some(inner);
                            break;
                        }
                    }
                    if first_string.is_some() {
                        break;
                    }
                }
            }
            if let Some(first) = first_string {
                let mut iw = first.walk();
                let frag_text = first
                    .named_children(&mut iw)
                    .find(|c| c.kind() == "string_content" || c.kind() == "string_fragment")
                    .and_then(|n| text_of(n, code));
                let raw = match frag_text {
                    Some(t) => t,
                    None => text_of(first, code)?,
                };
                let trimmed = strip_string_quotes_loose(&raw);
                if let Some(idx) = trimmed.find('{') {
                    let head = trimmed[..idx].to_string();
                    if !head.is_empty() {
                        return Some(head);
                    }
                } else if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            } else if let Some(prefix) = rust_macro_const_first_arg_prefix(cur, code) {
                // No literal first arg, but the first non-literal token is an
                // identifier that resolves to a top-level `const NAME: &str = "lit";`
                // declaration in the same file. Treat the const value as if it
                // had been written inline so `format!(URL_FMT, x)` locks the
                // host the same way `format!("https://api/{}", x)` does.
                return Some(prefix);
            }
        }
    }

    // Case 4: interpolated-string leading literal fragment.
    // Python f-strings parse as `formatted_string`; Ruby interpolated
    // strings parse as `string` with an `interpolation` child.  The
    // `string + has_interpolation child` gate keeps plain JS / TS /
    // Java `string` nodes (whose children are only
    // `string_content`/`string_fragment`) from accidentally seeding a
    // phantom prefix on every literal-URL call site.  PHP double-
    // quoted strings parse as `encapsed_string`, distinct kind, so
    // they don't trip this branch either.
    let is_fstring = cur.kind() == "formatted_string";
    let is_interp_string = cur.kind() == "string" && has_string_interpolation(cur);
    if is_fstring || is_interp_string {
        let mut w = cur.walk();
        let first = cur.named_children(&mut w).next()?;
        if matches!(first.kind(), "string_content" | "string_fragment") {
            let raw = text_of(first, code)?;
            let trimmed = strip_string_quotes_loose(&raw);
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    None
}

/// Resolve the leading prefix of a Rust `format!(IDENT, ...)`-style macro
/// when the first arg is a bare identifier bound to a top-level
/// `const NAME: &str = "literal";` or `static NAME: &str = "literal";`
/// declaration in the same file. Returns the leading literal text up to
/// the first `{` placeholder, or the whole literal when no placeholder is
/// present.
///
/// Walks the macro's `token_tree` for the first identifier (skipping the
/// `(` `)` `,` punctuation), then ascends to the file root and scans direct
/// `const_item` / `static_item` children for a name match. Bypasses inner
/// functions / impl blocks: only file-level declarations participate, which
/// keeps the lookup deterministic and avoids shadowing surprises.
fn rust_macro_const_first_arg_prefix(macro_node: Node, code: &[u8]) -> Option<String> {
    let token_tree = {
        let mut w = macro_node.walk();
        macro_node
            .named_children(&mut w)
            .find(|c| c.kind() == "token_tree")?
    };
    let first_ident_name = {
        let mut w = token_tree.walk();
        let mut found: Option<String> = None;
        for child in token_tree.named_children(&mut w) {
            match child.kind() {
                "string_literal" | "raw_string_literal" => return None,
                "identifier" => {
                    found = text_of(child, code);
                    break;
                }
                _ => continue,
            }
        }
        found?
    };
    let mut root = macro_node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut rw = root.walk();
    for child in root.named_children(&mut rw) {
        if !matches!(child.kind(), "const_item" | "static_item") {
            continue;
        }
        let name = child
            .child_by_field_name("name")
            .and_then(|n| text_of(n, code));
        if name.as_deref() != Some(first_ident_name.as_str()) {
            continue;
        }
        let value = child.child_by_field_name("value")?;
        let lit = if matches!(value.kind(), "string_literal" | "raw_string_literal") {
            value
        } else {
            continue;
        };
        let mut iw = lit.walk();
        let frag_text = lit
            .named_children(&mut iw)
            .find(|c| c.kind() == "string_content" || c.kind() == "string_fragment")
            .and_then(|n| text_of(n, code));
        let raw = match frag_text {
            Some(t) => t,
            None => text_of(lit, code)?,
        };
        let trimmed = strip_string_quotes_loose(&raw);
        if let Some(idx) = trimmed.find('{') {
            let head = trimmed[..idx].to_string();
            if !head.is_empty() {
                return Some(head);
            }
        } else if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    None
}

/// Strip surrounding `"`/`'`/`` ` `` quotes if present.
fn strip_string_quotes_loose(raw: &str) -> String {
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\''))
            || (raw.starts_with('`') && raw.ends_with('`')))
    {
        raw[1..raw.len() - 1].to_string()
    } else {
        raw.to_string()
    }
}

/// Extract the numeric literal operand from a binary expression.
///
/// When a binary expression has one identifier operand (captured in `uses`)
/// and one numeric literal operand, this returns the parsed literal value.
/// Used for abstract-domain transfer when the SSA only has the identifier use.
fn extract_bin_op_const(ast: Node, lang: &str, code: &[u8]) -> Option<i64> {
    let bin_expr = find_single_binary_expr(ast, lang)?;
    // Look for a numeric literal child
    let left = bin_expr.named_child(0)?;
    let right = bin_expr.named_child(1)?;

    fn try_parse_number(n: Node, code: &[u8]) -> Option<i64> {
        let kind = n.kind();
        if kind == "number"
            || kind == "integer"
            || kind == "integer_literal"
            || kind == "number_literal"
            || kind == "float"
        {
            let text = std::str::from_utf8(&code[n.byte_range()]).ok()?.trim();
            // Try standard decimal parse first
            if let Ok(v) = text.parse::<i64>() {
                return Some(v);
            }
            // Try hex (0x...), octal (0o...), binary (0b...) prefixed literals
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                return i64::from_str_radix(hex, 16).ok();
            }
            if let Some(oct) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
                return i64::from_str_radix(oct, 8).ok();
            }
            if let Some(bin) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
                return i64::from_str_radix(bin, 2).ok();
            }
            None
        } else {
            None
        }
    }

    // Try left, then right, one of them should be a literal
    try_parse_number(left, code).or_else(|| try_parse_number(right, code))
}

/// Detect whether the expression(s) in `ast` produce a boolean-only result
/// rooted in equality/inequality comparisons against literals.
///
/// True when `ast` is (or wraps) either:
/// - a direct equality comparison (`==` / `!=` / `===` / `!==`) with exactly
///   one literal operand, or
/// - a compound boolean expression (`&&`, `||`, `!`, `and`, `or`, `not`)
///   whose every leaf is a qualifying equality comparison.
///
/// Covers JS/TS `binary_expression`, Python `comparison_operator`, Ruby
/// `binary`, and languages that share the `binary_expression` kind (Java, Go,
/// PHP, C/C++, Rust). Compound chains like `a === 'x' || b === 'y'` qualify
/// because their result is provably a boolean even though the taint engine
/// sees all leaf operands on a single CFG Assign node.
///
/// The SSA taint transfer uses this flag to suppress propagation of operand
/// taint into the boolean result: the outcome carries no attacker-controlled
/// data, so downstream ternaries/branches should not inherit operand caps.
pub(super) fn detect_eq_with_const(ast: Node, lang: &str) -> bool {
    // Prefer inspecting the RHS of assignment-like wrappers, so flags on e.g.
    // `var ok = a === 'x' || b === 'y'` examine the full right-hand side.
    let target = assignment_rhs(ast).unwrap_or(ast);
    is_boolean_eq_const_tree(target, lang)
}

/// Recursive predicate: does `node` evaluate to a boolean whose value is
/// determined solely by equality comparisons against literals, joined by
/// boolean operators? Parentheses, `!`/`not`, and `&&`/`||`/`and`/`or` are
/// transparent; every leaf must be a direct equality-with-constant.
fn is_boolean_eq_const_tree(node: Node, lang: &str) -> bool {
    match node.kind() {
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|c| is_boolean_eq_const_tree(c, lang)),
        "unary_expression" | "not_operator" => {
            // `!` / `not`, operator is an anonymous child; operand is the
            // single named child.
            let mut w = node.walk();
            let mut op_is_not = false;
            for child in node.children(&mut w) {
                if !child.is_named() && matches!(child.kind(), "!" | "not") {
                    op_is_not = true;
                    break;
                }
            }
            if !op_is_not {
                return false;
            }
            node.named_child(0)
                .is_some_and(|c| is_boolean_eq_const_tree(c, lang))
        }
        "boolean_operator" => {
            // Python `and`/`or`, operands are named children.
            let l = node.named_child(0);
            let r = node.named_child(1);
            l.is_some_and(|n| is_boolean_eq_const_tree(n, lang))
                && r.is_some_and(|n| is_boolean_eq_const_tree(n, lang))
        }
        _ => {
            if !is_binary_expr_kind(node.kind(), lang) {
                return false;
            }
            let op = binary_operator_token(node);
            match op.as_deref() {
                Some("&&") | Some("||") | Some("and") | Some("or") => {
                    node.named_child(0)
                        .is_some_and(|l| is_boolean_eq_const_tree(l, lang))
                        && node
                            .named_child(1)
                            .is_some_and(|r| is_boolean_eq_const_tree(r, lang))
                }
                Some("==") | Some("===") | Some("!=") | Some("!==") => {
                    let Some(left) = node.named_child(0) else {
                        return false;
                    };
                    let Some(right) = node.named_child(1) else {
                        return false;
                    };
                    let left_lit = is_equality_literal_kind(left.kind());
                    let right_lit = is_equality_literal_kind(right.kind());
                    // Exactly one side literal. Both-literal is constant-fold
                    // territory; neither-literal is a generic identity check
                    // whose operands may both be tainted.
                    left_lit ^ right_lit
                }
                _ => false,
            }
        }
    }
}

/// Return the anonymous operator token text of a binary expression node.
fn binary_operator_token(node: Node) -> Option<String> {
    let mut w = node.walk();
    for child in node.children(&mut w) {
        if !child.is_named() {
            return Some(child.kind().to_string());
        }
    }
    None
}

/// Property names whose value is provably an integer across the supported
/// languages: JS/TS `arr.length` (Array/String/TypedArray), `map.size`
/// (Map/Set), `buffer.byteLength` (ArrayBuffer/TypedArray); Python `.count`
/// (`str.count`, `list.count`, `tuple.count`, all return int); Ruby `.length`
/// / `.size` / `.count`; Java `.size()` / `.length()`; Rust `.len()`.  This
/// list is intentionally narrow, only properties whose semantics across every
/// host we scan return an integer, so the `TypeKind::Int` fact is sound.
fn is_numeric_length_property(name: &str) -> bool {
    matches!(name, "length" | "size" | "byteLength" | "count" | "len")
}

/// Detect whether this CFG node is a read of a numeric-length property on a
/// container.  Covers both pure property access (`arr.length` as the RHS of
/// an assignment or declaration) and zero-argument method calls
/// (`list.size()`, `vec.len()`).  Returns `true` when the relevant value
/// expression is a `member_expression` / `attribute` / `selector_expression`
/// / `field_expression` whose property leaf matches
/// [`is_numeric_length_property`], or a zero-arg call around such an
/// expression.
///
/// Consumed by the type-fact analysis (`ssa::type_facts::analyze_types`) to
/// infer `TypeKind::Int` on the defined value so sink-cap suppression can
/// treat `"row " + arr.length` as a non-injectable payload.
/// when the RHS of an assignment / declaration is a single
/// member-access expression (`let x = dto.email`, `x = obj.field`,
/// `let x = obj["field"]`), return the property name.  The CFG type-fact
/// analysis uses the recovered name to look up the field's declared
/// [`crate::ssa::type_facts::TypeKind`] when the receiver is a
/// [`crate::ssa::type_facts::TypeKind::Dto`].
///
/// Returns `None` for any other shape (function calls, complex
/// expressions, computed-key subscripts, optional-chaining, etc.) so
/// the legacy copy-prop / Unknown propagation continues to apply.
fn detect_member_field_assignment(ast: Node, code: &[u8]) -> Option<String> {
    // Pull the RHS the same way `detect_numeric_length_access` does so
    // both detectors look at the same node grain.
    let target = ast
        .child_by_field_name("value")
        .or_else(|| ast.child_by_field_name("right"))
        .or_else(|| {
            let mut cursor = ast.walk();
            ast.named_children(&mut cursor)
                .find(|c| matches!(c.kind(), "variable_declarator" | "init_declarator"))
                .and_then(|d| {
                    d.child_by_field_name("value")
                        .or_else(|| d.child_by_field_name("initializer"))
                })
        })
        .or_else(|| {
            // Python wraps assignment in `expression_statement`; drill into
            // the inner `assignment` node to reach its `right` field.  Ruby
            // wraps simple `x = rhs` in `assignment` directly so this arm is
            // a no-op for Ruby, but the Python case is load-bearing for the
            // `qs = User.objects` shape where `member_field` drives the
            // Django ORM type-fact tagging.
            let mut cursor = ast.walk();
            ast.named_children(&mut cursor)
                .find(|c| matches!(c.kind(), "assignment"))
                .and_then(|a| a.child_by_field_name("right"))
        })
        .unwrap_or(ast);
    extract_member_field_name(target, code)
}

fn extract_member_field_name(node: Node, code: &[u8]) -> Option<String> {
    match node.kind() {
        // JS / TS / Java / C / C++ / Go (selector) / Rust (field).
        "member_expression"
        | "member_access_expression"
        | "field_expression"
        | "selector_expression"
        | "attribute" => {
            let prop = node
                .child_by_field_name("property")
                .or_else(|| node.child_by_field_name("attribute"))
                .or_else(|| node.child_by_field_name("field"))
                .or_else(|| node.child_by_field_name("name"))?;
            let text = text_of(prop, code)?;
            // Defensive: reject anything that doesn't look like an
            // identifier (e.g. numeric subscripts).  Allows ASCII
            // letters / digits / underscore.
            if text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !text.is_empty() {
                Some(text)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn detect_numeric_length_access(ast: Node, _lang: &str, code: &[u8]) -> bool {
    // Pull the value expression for variable declarations / assignments.
    // Other node shapes (e.g. plain member-expression reads) are checked
    // as-is.
    let target = ast
        .child_by_field_name("value")
        .or_else(|| ast.child_by_field_name("right"))
        .or_else(|| {
            let mut cursor = ast.walk();
            ast.named_children(&mut cursor)
                .find(|c| matches!(c.kind(), "variable_declarator" | "init_declarator"))
                .and_then(|d| {
                    d.child_by_field_name("value")
                        .or_else(|| d.child_by_field_name("initializer"))
                })
        })
        .unwrap_or(ast);
    is_numeric_length_access_expr(target, code)
}

fn is_numeric_length_access_expr(node: Node, code: &[u8]) -> bool {
    match node.kind() {
        "member_expression"
        | "attribute"
        | "selector_expression"
        | "field_expression"
        | "member_access_expression" => {
            let prop = node
                .child_by_field_name("property")
                .or_else(|| node.child_by_field_name("attribute"))
                .or_else(|| node.child_by_field_name("field"))
                .or_else(|| node.child_by_field_name("name"));
            prop.and_then(|p| text_of(p, code))
                .is_some_and(|t| is_numeric_length_property(&t))
        }
        // Zero-arg method call: `list.size()` / `vec.len()` / `str.length()`.
        "call_expression" | "method_invocation" | "method_call_expression" | "call" => {
            let args = node
                .child_by_field_name("arguments")
                .or_else(|| node.child_by_field_name("argument_list"));
            let arity = args
                .map(|a| {
                    let mut c = a.walk();
                    a.named_children(&mut c).count()
                })
                .unwrap_or(0);
            if arity != 0 {
                return false;
            }
            let callee = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("name"))
                .or_else(|| node.child_by_field_name("method"));
            match callee {
                Some(c) => is_numeric_length_access_expr(c, code),
                None => false,
            }
        }
        _ => false,
    }
}

/// Literal kinds accepted for equality-with-constant detection. Conservatively
/// limited to scalar literals across the supported tree-sitter grammars.
fn is_equality_literal_kind(kind: &str) -> bool {
    matches!(
        kind,
        // Strings
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "encapsed_string"
            // Numbers
            | "number"
            | "integer"
            | "float"
            | "integer_literal"
            | "float_literal"
            | "number_literal"
            | "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_floating_point_literal"
            // Null / nil / none / undefined
            | "null"
            | "null_literal"
            | "nil"
            | "none"
            | "undefined"
            // Booleans
            | "true"
            | "false"
            | "boolean_literal"
    )
}

/// Find a single binary expression node at or directly under `ast`.
///
/// Returns `None` if there are zero or multiple binary expressions
/// (ambiguous). Only descends one level into assignment/expression wrappers.
fn find_single_binary_expr<'a>(ast: Node<'a>, lang: &str) -> Option<Node<'a>> {
    let ast_kind = ast.kind();

    // Check if ast itself is a binary expression
    if is_binary_expr_kind(ast_kind, lang) {
        // Verify it has exactly 2 named children (left, right), no nesting
        let named_count = ast.named_child_count();
        if named_count == 2 {
            // Ensure neither child is itself a binary expression (that would
            // mean the operator is for a compound expression like `a + b * c`)
            let left = ast.named_child(0);
            let right = ast.named_child(1);
            let left_is_bin = left.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
            let right_is_bin = right.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
            if !left_is_bin && !right_is_bin {
                return Some(ast);
            }
        }
        return None; // Nested or complex
    }

    // Check one level down for assignment wrappers, expression statements, etc.
    let wrapper_kinds = [
        "expression_statement",
        "assignment_expression",
        "assignment",
        "variable_declaration",
        "variable_declarator",
        "short_var_declaration",
        "lexical_declaration",
    ];
    if wrapper_kinds.contains(&ast_kind) || ast_kind.ends_with("_statement") {
        let mut found: Option<Node<'a>> = None;
        let mut cursor = ast.walk();
        for child in ast.named_children(&mut cursor) {
            if is_binary_expr_kind(child.kind(), lang) {
                if found.is_some() {
                    return None; // Multiple binary expressions → ambiguous
                }
                // Same check: must have exactly 2 non-binary named children
                if child.named_child_count() == 2 {
                    let l = child.named_child(0);
                    let r = child.named_child(1);
                    let l_bin = l.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
                    let r_bin = r.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
                    if !l_bin && !r_bin {
                        found = Some(child);
                    }
                }
            } else if wrapper_kinds.contains(&child.kind()) {
                // Recurse one more level into nested wrappers (e.g.,
                // variable_declaration → variable_declarator → binary_expression)
                let mut inner_cursor = child.walk();
                for grandchild in child.named_children(&mut inner_cursor) {
                    if is_binary_expr_kind(grandchild.kind(), lang) {
                        if found.is_some() {
                            return None;
                        }
                        if grandchild.named_child_count() == 2 {
                            let l = grandchild.named_child(0);
                            let r = grandchild.named_child(1);
                            let l_bin = l.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
                            let r_bin = r.is_some_and(|n| is_binary_expr_kind(n.kind(), lang));
                            if !l_bin && !r_bin {
                                found = Some(grandchild);
                            }
                        }
                    }
                }
            }
        }
        return found;
    }

    None
}

/// Check if an AST node kind is a binary expression in the given language.
///
/// Python uses `binary_operator` for arithmetic/bitwise and
/// `comparison_operator` for comparisons. Chained Python comparisons
/// (`a < b < c`) have 3+ named children and are rejected by the
/// `named_child_count() == 2` guard in `find_single_binary_expr`.
fn is_binary_expr_kind(kind: &str, lang: &str) -> bool {
    match lang {
        "python" => kind == "binary_operator" || kind == "comparison_operator",
        "ruby" => kind == "binary",
        _ => kind == "binary_expression",
    }
}

/// Create a node in one short borrow and optionally attach a taint label.
#[allow(clippy::too_many_arguments)]
pub(super) fn push_node<'a>(
    g: &mut Cfg,
    kind: StmtKind,
    ast: Node<'a>,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
    call_ordinal: u32,
    analysis_rules: Option<&LangAnalysisRules>,
) -> NodeIndex {
    /* ── 1.  IDENTIFIER EXTRACTION ─────────────────────────────────────── */

    // Primary guess (varies by AST kind)
    let mut text = match lookup(lang, ast.kind()) {
        // plain `foo(bar)` style call
        Kind::CallFn => ast
            .child_by_field_name("function")
            .or_else(|| ast.child_by_field_name("method"))
            .or_else(|| ast.child_by_field_name("name"))
            .or_else(|| ast.child_by_field_name("type"))
            // JS/TS `new_expression` uses `constructor` field.
            .or_else(|| ast.child_by_field_name("constructor"))
            // Fallback for constructors whose grammar lacks field names
            // (e.g. PHP `object_creation_expression` has positional children).
            .or_else(|| find_constructor_type_child(ast))
            .and_then(|n| {
                // IIFE: `(function(x){...})(arg)`, the called expression is a
                // function literal with no identifier. Bind the call to the
                // anonymous body's synthetic name so resolve_callee can find
                // the extracted BodyCfg/summary. Without this, text_of() would
                // return the function's full source slice, which matches no
                // summary key.
                let unwrapped = unwrap_parens(n);
                if lookup(lang, unwrapped.kind()) == Kind::Function {
                    Some(anon_fn_name(unwrapped.start_byte()))
                } else {
                    text_of(n, code)
                }
            })
            .unwrap_or_default(),

        // method / UFCS call  `recv.method()`  or  `Type::func()`
        Kind::CallMethod => {
            let func = ast
                .child_by_field_name("method")
                .or_else(|| ast.child_by_field_name("name"))
                .and_then(|n| text_of(n, code));
            let recv = ast
                .child_by_field_name("object")
                .or_else(|| ast.child_by_field_name("receiver"))
                .or_else(|| ast.child_by_field_name("scope"))
                .and_then(|n| root_receiver_text(n, lang, code));
            match (recv, func) {
                (Some(r), Some(f)) => format!("{r}.{f}"),
                (_, Some(f)) => f,
                _ => String::new(),
            }
        }

        // `my_macro!(…)`
        Kind::CallMacro => ast
            .child_by_field_name("macro")
            .and_then(|n| text_of(n, code))
            .map(|raw| rewrite_rust_bare_join_macro(&raw, ast, lang, code).unwrap_or(raw))
            .unwrap_or_default(),

        // Function definitions: use just the function name, not the full
        // body text.  The raw body text can spuriously match label rules
        // (e.g. `def search\n  find_by_sql(…)\nend` would suffix-match
        // the `find_by_sql` sink via the `head = text.split('(')` logic
        // in classify_all).
        Kind::Function => ast
            .child_by_field_name("name")
            .or_else(|| ast.child_by_field_name("declarator"))
            .and_then(|n| text_of(n, code))
            .unwrap_or_default(),

        // everything else – fallback to raw slice
        _ => text_of(ast, code).unwrap_or_default(),
    };

    // C++ new/delete: normalize callee to "new"/"delete" for resource pair
    // matching.  Without this, new_expression extracts the type name (e.g.
    // "int") and delete_expression extracts the full expression text.
    // Guarded to C++ only so JS/TS `new_expression` is unaffected.
    if lang == "cpp" {
        if ast.kind() == "new_expression" {
            text = "new".to_string();
        } else if ast.kind() == "delete_expression" {
            text = "delete".to_string();
        }
    }

    // Ruby backtick shell execution: the `subshell` AST node has no
    // `function`/`method` field so the CallFn text extraction above yields
    // "".  Stamp a synthetic callee name so the Sink(SHELL_ESCAPE) rule in
    // labels/ruby.rs fires.
    if lang == "ruby" && ast.kind() == "subshell" {
        text = "subshell".to_string();
    }

    // JS/TS `for (… of iter)` / `for (… in iter)` / `for await (… of iter)`:
    // tree-sitter classifies all three as `for_in_statement` with the
    // iterator on the `right` field.  Use the iterator expression's text
    // (e.g. `"req.body"`) for label classification so the loop binding
    // inherits a Source taint when the iterator matches a Source rule.
    // Without this, the for_in_statement's text is the full multi-line
    // loop, which never matches any short suffix-style Source matcher.
    //
    // Phase 03 originally proposed narrowing this rewrite to the
    // `for await` form alone (where the iterator text classification
    // was the immediate motivation).  The rewrite is kept broader here
    // because the same iterator-text classification benefits plain
    // `for (const x of req.body)` and `for (const k in process.env)`
    // identically — the loop-binding-inherits-iterator-taint semantics
    // are uniform across all three forms, and narrowing would create
    // an arbitrary distinction the source rules would have to mirror.
    if matches!(lang, "javascript" | "typescript" | "tsx")
        && ast.kind() == "for_in_statement"
        && let Some(right) = ast.child_by_field_name("right")
        && let Some(iter_text) = text_of(right, code)
    {
        text = iter_text;
    }

    // Python `for x in iter:` / `async for x in iter:`: tree-sitter-python
    // emits both shapes as `for_statement` (the `async` keyword is an
    // unnamed leaf child).  Same loop-binding-inherits-iterator-taint
    // semantics as the JS rewrite above: classify against the iterator
    // text so a `Source` matcher on `request.json` lights up when the
    // loop iterates an awaitable request body.
    if lang == "python"
        && ast.kind() == "for_statement"
        && let Some(right) = ast.child_by_field_name("right")
        && let Some(iter_text) = text_of(right, code)
    {
        text = iter_text;
    }

    // If this is a declaration/expression wrapper or an assignment that
    // *contains* a call, prefer the first inner call identifier instead of
    // the whole line.  Track the inner call's byte span so we can populate
    // `CallMeta.callee_span` once the labels settle, enabling narrow
    // source-location reporting when the classified call lives several lines
    // below the enclosing statement (e.g. call inside a multi-line template
    // literal).
    let mut inner_text_span: Option<(usize, usize)> = None;
    if matches!(
        lookup(lang, ast.kind()),
        Kind::CallWrapper | Kind::Assignment | Kind::Return
    ) {
        if let Some((inner, inner_span)) = first_call_ident_with_span(ast, lang, code) {
            text = inner;
            inner_text_span = Some(inner_span);
        } else if matches!(lookup(lang, ast.kind()), Kind::CallWrapper) {
            // Fallback for language-construct "calls" (e.g. PHP `echo_statement`,
            // `print` expression):  the first child is a keyword leaf (e.g. "echo")
            // that acts as a callee but is not a function_call_expression.
            let mut cursor = ast.walk();
            if let Some(first) = ast.children(&mut cursor).next()
                && first.child_count() == 0
                && let Some(kw) = text_of(first, code)
                && kw.len() <= 16
            {
                text = kw;
                inner_text_span = Some((first.start_byte(), first.end_byte()));
            }
        }
    }

    /* ── 2.  LABEL LOOK-UP  ───────────────────────────────────────────── */

    let extra = analysis_rules.map(|r| r.extra_labels.as_slice());
    let mut labels = classify_all(lang, &text, extra);

    // Rust chain-text classification.  The default `text` for a Rust
    // CallMethod is `{root_receiver}.{method}`, where `root_receiver`
    // is the leftmost identifier after walking through every nested
    // call/method receiver.  That convention loses the intermediate
    // chain methods, so a body-binding chain like
    // `Client::post(url).body(payload).send()` reduces to
    // `Client::post.send` and rules keyed on `body.send` /
    // `RequestBuilder.body` cannot fire.
    //
    // Reclassify against the call-AST's source text (with paren groups
    // stripped) so suffix matchers covering chain shapes
    // (`body.send`, `body_string`, `Request::builder.body`, ...) attach.
    // Strictly additive: we union new labels with the existing ones,
    // never override.  Limited to Rust to avoid disturbing the other
    // languages' chain conventions.
    if lang == "rust" {
        if let Some(cn) = find_call_node(ast, lang) {
            if let Some(chain_raw) = text_of(cn, code) {
                // Multi-line Rust chains (`Client::new()\n  .post(url)\n
                // .body(p)\n  .send()`) preserve interior whitespace in
                // the source slice, which would prevent suffix matchers
                // like `body.send` from firing.  Strip whitespace before
                // normalizing paren groups, mirroring the same trick
                // used by `find_chained_inner_call` for JS/TS chains.
                let chain_compact: String =
                    chain_raw.chars().filter(|c| !c.is_whitespace()).collect();
                let chain_text = crate::labels::normalize_chained_call_for_classify(&chain_compact);
                if chain_text != text {
                    let chain_labels = classify_all(lang, &chain_text, extra);
                    for l in chain_labels {
                        if !labels.contains(&l) {
                            labels.push(l);
                        }
                    }
                }
                // Also try classification against the chain with
                // trailing identity methods peeled.  Rust chains often
                // end in `.unwrap()` / `.expect("...")` / `.await` /
                // `.clone()` etc., which obscure the body-bind verb
                // for suffix matchers.  E.g. hyper's
                // `Request::builder().method(..).uri(..).body(p).unwrap()`
                // peels to `...body`, allowing a simpler `body` /
                // `Request::builder.body` matcher to fire.
                let peeled = crate::ssa::type_facts::peel_identity_suffix(&chain_text);
                if peeled != chain_text && peeled != text {
                    let peeled_labels = classify_all(lang, &peeled, extra);
                    for l in peeled_labels {
                        if !labels.contains(&l) {
                            labels.push(l);
                        }
                    }
                }
                // Pattern synthesis: the hyper request-builder chain
                // (`hyper::Request::builder().method(..).uri(..).body(p)`)
                // can interleave `.method`, `.uri`, `.header`, `.version`
                // etc. between `Request::builder` and the body-bind step.
                // Suffix matchers can't span those, so synthesise a
                // DATA_EXFIL sink whenever the chain begins with
                // `Request::builder` and ends in a body-binding verb.
                // Strictly additive: no labels are removed, only added,
                // and the synthesis only fires when an explicit Sink
                // hasn't already attached.
                let chain_for_synth = if peeled != chain_text {
                    &peeled
                } else {
                    &chain_text
                };
                if !labels
                    .iter()
                    .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(crate::labels::Cap::DATA_EXFIL)))
                    && (chain_for_synth.contains("Request::builder.")
                        || chain_for_synth.contains("hyper::Request::builder."))
                {
                    let last_seg =
                        chain_for_synth.rsplit('.').next().unwrap_or(chain_for_synth);
                    if matches!(
                        last_seg,
                        "body" | "body_mut" | "body_string" | "body_json" | "body_bytes"
                    ) {
                        labels.push(DataLabel::Sink(crate::labels::Cap::DATA_EXFIL));
                    }
                }
            }
        }
    }

    // If the outermost call didn't classify, try inner/nested calls.
    // E.g. `str(eval(expr))`, `str` is not a sink, but `eval` is.
    // When the callee is overridden, save the original for container ops
    // (e.g. `parts.add(req.getParameter(...))`, callee becomes
    // "req.getParameter" but outer_callee preserves "parts.add").
    //
    // Statement-level calls in languages without a separate
    // `expression_statement` wrapper (Ruby, where `body_statement` directly
    // contains the call AST node) reach `push_node` with `ast.kind() ==
    // "call"` (`Kind::CallMethod`) rather than `Kind::CallWrapper`.  Without
    // including the call kinds in the gate, an unclassified outer wrapper
    // around a sink (e.g. `YAML.safe_load(File.read(filename))` or
    // `String.new(File.read(x))`) loses the inner sink's classification
    // entirely — the outer call becomes a non-sink node, and the inner call
    // is not emitted as a standalone CFG node because it sits inside the
    // outer's `argument_list`.  Cross-function summary extraction then
    // misses the `param_to_sink` for the wrapper helper, breaking detection
    // of every chain-style sink wrapper used in real Ruby CVEs (rswag
    // CVE-2023-38337, the Marshal/JSON/YAML-of-File.read pattern, etc.).
    let mut outer_callee: Option<String> = None;
    let mut inner_callee_span: Option<(usize, usize)> = None;
    // JS/TS Promise callback methods (`.then`/`.catch`/`.finally`) on chained
    // receivers (`Promise.resolve(req.body).then(cb)`).  Without this guard,
    // `find_classifiable_inner_call` walks into the chain receiver and
    // rewrites `text` from `.then` to `Promise.resolve` (which classifies as
    // a Source), erasing the outer call's identity.  The SSA layer then
    // never sees a `then` callee, so `try_apply_promise_callback` never
    // fires and taint on the resolved value is dropped.  Detect the outer
    // promise-callback method here and skip the rewrite — the outer call's
    // identity is preserved, and the inner Promise.resolve's argument
    // taint flows through `info.taint.uses` (implicit args) as the
    // promise-callback handler already expects.
    let outer_is_promise_callback = matches!(lang, "javascript" | "typescript" | "tsx")
        && find_call_node(ast, lang)
            .and_then(|cn| {
                cn.child_by_field_name("function")
                    .or_else(|| cn.child_by_field_name("method"))
            })
            .and_then(|fc| {
                if matches!(fc.kind(), "member_expression" | "attribute") {
                    fc.child_by_field_name("property")
                        .or_else(|| fc.child_by_field_name("name"))
                        .and_then(|p| text_of(p, code))
                } else {
                    None
                }
            })
            .is_some_and(|leaf| crate::labels::is_promise_callback_method(lang, &leaf));
    if labels.is_empty()
        && matches!(
            lookup(lang, ast.kind()),
            Kind::CallWrapper
                | Kind::Assignment
                | Kind::Return
                | Kind::CallFn
                | Kind::CallMethod
                | Kind::CallMacro
        )
        && let Some((inner_text, inner_label, inner_span)) =
            find_classifiable_inner_call(ast, lang, code, extra)
    {
        labels.push(inner_label);
        if !outer_is_promise_callback {
            outer_callee = Some(text.clone());
            text = inner_text;
            inner_callee_span = Some(inner_span);
        }
    }

    // For assignments like `element.innerHTML = value`, the inner-call heuristic
    // above may have overridden `text` with a call on the RHS (e.g. getElementById).
    // If that didn't produce a label, check the LHS property name, it may be a
    // sink like `innerHTML`.
    //
    // This covers both direct `Kind::Assignment` nodes and `Kind::CallWrapper`
    // nodes (expression_statement) that wrap an assignment.
    if labels.is_empty() {
        let assign_node = if matches!(lookup(lang, ast.kind()), Kind::Assignment) {
            Some(ast)
        } else if matches!(lookup(lang, ast.kind()), Kind::CallWrapper) {
            // Walk children to find a nested assignment_expression
            let mut cursor = ast.walk();
            ast.children(&mut cursor)
                .find(|c| matches!(lookup(lang, c.kind()), Kind::Assignment))
        } else {
            None
        };

        if let Some(assign) = assign_node
            && let Some(lhs) = assign.child_by_field_name("left")
        {
            // Try full member expression first (e.g. "location.href"), more
            // specific and avoids false positives on `a.href`.
            if let Some(full) = member_expr_text(lhs, code) {
                if let Some(l) = classify(lang, &full, extra) {
                    labels.push(l);
                }
            }
            // Fall back to property-only (e.g. "innerHTML") for sinks that
            // don't need object context.
            if labels.is_empty()
                && let Some(prop) = lhs.child_by_field_name("property")
                && let Some(prop_text) = text_of(prop, code)
            {
                if let Some(l) = classify(lang, &prop_text, extra) {
                    labels.push(l);
                }
            }
            // Subscript-set form: `response.headers["X-Foo"] = bar`
            // (Ruby `element_reference`, JS/TS `subscript_expression`,
            // Python `subscript`).  The LHS has no `property` field, so
            // walk into the subscript's `object` and try classifying its
            // member-expression text (e.g. `response.headers`).  This
            // lets header-injection sinks fire on the bare bracket form
            // alongside the `set_header` / `headers_mut.insert` method
            // shapes already covered above.
            if labels.is_empty()
                && matches!(
                    lhs.kind(),
                    "subscript_expression" | "subscript" | "element_reference"
                )
            {
                let obj = lhs
                    .child_by_field_name("object")
                    .or_else(|| lhs.child_by_field_name("value"))
                    .or_else(|| lhs.child(0));
                if let Some(obj_node) = obj
                    && let Some(obj_text) = member_expr_text(obj_node, code)
                    && let Some(l) = classify(lang, &obj_text, extra)
                {
                    labels.push(l);
                }
            }
        }
    }

    // For declarations/assignments whose RHS is a member expression (not a call),
    // try to classify the member expression text as a source.
    // This handles `var x = process.env.CMD` (JS), `os.environ["KEY"]` (Python),
    // and similar property-access-based source patterns.
    // Skip when the assignment's RHS is itself a function/lambda literal ,
    // labels found by `first_member_label` would come from inside the
    // closure body and shouldn't tag the outer wrapper (e.g. Go's
    // `run := func() { exec.Command(...) }` would otherwise inherit
    // `exec.Command`'s Sink label).  The function literal is handled as
    // its own scope by `collect_nested_function_nodes`.
    if labels.is_empty()
        && matches!(
            lookup(lang, ast.kind()),
            Kind::CallWrapper | Kind::Assignment
        )
        && !rhs_is_function_literal(ast, lang)
        && let Some(found) = first_member_label(ast, lang, code, extra)
    {
        labels.push(found);
        // Update text so the callee name reflects the source.
        // Preserve the original callee in outer_callee so inter-procedural
        // summary resolution can still find the wrapping function
        // (e.g. `storeInto(req.query.input, items)` → callee="req.query.input"
        // but outer_callee="storeInto").
        //
        // Skip the text rewrite when the outer call is a JS/TS promise
        // callback method (`.then`/`.catch`/`.finally`).  The `.then` call
        // node must keep its `then` callee text so `try_apply_promise_callback`
        // and the synthetic `source_to_callback` emission recognise it.
        // The Source label still attaches, so the resolved-value taint
        // flows from the inner `Promise.resolve(req.body)`.
        if !outer_is_promise_callback {
            if let Some(member_text) = first_member_text(ast, code) {
                if outer_callee.is_none() && text != member_text {
                    outer_callee = Some(text.clone());
                }
                text = member_text;
            }
        }
    }

    // For `if let` / `while let` patterns: try to classify the value expression
    // in the let-condition as a source/sink.  E.g. `if let Ok(cmd) = env::var("CMD")`
    // should recognise `env::var` as a taint source and label this node accordingly.
    if labels.is_empty()
        && matches!(lookup(lang, ast.kind()), Kind::If | Kind::While)
        && let Some(cond) = ast.child_by_field_name("condition")
        && cond.kind() == "let_condition"
        && let Some(val) = cond.child_by_field_name("value")
    {
        if let Some((ident, ident_span)) = first_call_ident_with_span(val, lang, code)
            && let Some(l) = classify(lang, &ident, extra)
        {
            labels.push(l);
            text = ident;
            if inner_text_span.is_none() {
                inner_text_span = Some(ident_span);
            }
        }
        if labels.is_empty()
            && let Some(ident_text) = text_of(val, code)
            && let Some(l) = classify(lang, &ident_text, extra)
        {
            labels.push(l);
            text = ident_text;
        }
    }

    // Hoist call-node lookup: reused for gated sinks and arg_uses.
    let mut call_ast = find_call_node(ast, lang);

    // Chained-call inner-gate rebinding.  When the outer call is a method-
    // chain wrapper whose receiver is itself a call to a known gated sink
    // (e.g. `http.get(uri, cb).on('error', e => ...)` or
    // `axios.get(url).then(handler).catch(handler)`), the outer callee
    // (`.on`, `.catch`) doesn't classify and the inner sink is invisible to
    // gate classification + arg-use extraction.  Rebind to the inner call
    // so its sink fires and its args are checked.
    //
    // Only fires when:
    //   * `labels.is_empty()` (the outer call is non-classified)
    //   * the chain has a real inner call_expression
    //   * that inner callee actually matches a gate matcher for this lang
    //
    // Motivated by CVE-2025-64430 (Parse Server SSRF).
    if labels.is_empty()
        && let Some(outer) = call_ast
        && let Some((inner, inner_callee_text)) = find_chained_inner_call(outer, lang, code)
        && !classify_gated_sink(lang, &inner_callee_text, |_| None, |_| None, |_| false).is_empty()
    {
        call_ast = Some(inner);
        outer_callee = Some(text.clone());
        text = inner_callee_text;
        inner_callee_span = Some((inner.start_byte(), inner.end_byte()));
    }

    // Gated sinks: argument-sensitive classification (e.g., setAttribute).
    // Runs for any node containing a classifiable call, regardless of StmtKind.
    //
    // Prefer the shallow `call_ast` from `find_call_node` when available, but
    // fall back to a deeper walk (up to 4 levels) so wrapped calls still reach
    // the gate. This is necessary for forms like `var r = await fetch(url)`
    // (variable_declaration > variable_declarator > await_expression >
    // call_expression) where the call sits at depth 3. When using the deeper
    // walker we must also derive the callee text from the inner call node, not
    // the outer statement `text`, so gate matcher names like `"fetch"` hit.
    let mut sink_payload_args: Option<Vec<usize>> = None;
    let mut destination_uses: Option<Vec<String>> = None;
    let mut gate_filters: Vec<GateFilter> = Vec::new();
    // Gates run when no flat `Sink` label is already present, OR when a
    // matching gate restricts the payload-arg set on top of an existing flat
    // sink.  Source / Sanitizer labels are orthogonal — a callee like
    // Python's `requests.post` is a `Source` for its response object AND a
    // gated `Sink` for its URL/body argument positions; both should attach.
    //
    // Payload-arg refinement: when a flat sink matches a callee that ALSO
    // has a gate entry restricting `payload_args`, the gate's `payload_args`
    // are propagated to `sink_payload_args` so only those positions are
    // taint-checked.  Example: `execSync(cmd, { env: process.env })` matches
    // the bare `execSync` flat `Sink(SHELL_ESCAPE)` AND the gate `=execSync`
    // with `payload_args: &[0]`; without the refinement, the flat rule's
    // implicit "all args" would flag `process.env` flowing into the options
    // object's `env` field.  The gate's labels themselves are deduped so a
    // single capability never double-attributes.
    let has_sink_label = labels.iter().any(|l| matches!(l, DataLabel::Sink(_)));
    {
        let gate_call = call_ast.or_else(|| find_call_node_deep(ast, lang, 4));
        if let Some(cn) = gate_call {
            // Derive the gate's callee text from the call's
            // `function`/`method`/`name` field, falling back to `text`.
            //
            // The default is `text`, which by this point reflects the
            // qualified callee for method calls (`Velocity.evaluate`,
            // `$smarty->fetch`) reconstructed in the `Kind::CallMethod`
            // arm.  When `first_member_label` rewrites `text` to a member
            // Source like `req.body` (because the wrapper carries one as
            // an argument), the rewrite is correct for source attribution
            // but defeats gate matching against a bare callee
            // (`setValue(target, req.body, …)` would gate-match
            // `req.body` instead of `setValue`).
            //
            // Detect that case structurally: a Source label is present AND
            // the call's function-field text differs from `text`.  The
            // function field carries the actual callee identifier; when it
            // disagrees with `text`, `text` was clobbered by a member-source
            // override and the function field is the right gate target.
            // Whitespace is stripped to mirror `find_chained_inner_call`
            // so multi-line chains (`http\n  .get(...)`) still match flat
            // gate matchers like `http.get`.
            let function_field_text: Option<String> = cn
                .child_by_field_name("function")
                .or_else(|| cn.child_by_field_name("method"))
                .or_else(|| cn.child_by_field_name("name"))
                .and_then(|f| text_of(f, code))
                .map(|t| t.chars().filter(|c| !c.is_whitespace()).collect::<String>());
            let has_source_label = labels
                .iter()
                .any(|l| matches!(l, crate::labels::DataLabel::Source(_)));
            // Clippy flags one branch's clone as redundant because it cannot
            // see that `text` is read after this `let` (further down in this
            // function); silence the false positive without restructuring.
            #[allow(clippy::redundant_clone)]
            let gate_callee_text = if let Some(ff) = function_field_text.as_deref()
                && has_source_label
                && ff != text.as_str()
            {
                ff.to_string()
            } else if call_ast.is_some() {
                text.clone()
            } else {
                function_field_text.unwrap_or_else(|| text.clone())
            };
            let matches = classify_gated_sink(
                lang,
                &gate_callee_text,
                |idx| {
                    extract_const_string_arg(cn, idx, code).or_else(|| {
                        // C/C++ preprocessor macros and PHP `define`d constants
                        // surface as identifier nodes, not string literals.
                        // Ruby option constants (e.g.
                        // `Nokogiri::XML::ParseOptions::NOENT`) surface as
                        // `scope_resolution` / `constant` nodes.  Falling back
                        // to the macro-arg extractor for those languages lets
                        // gates like `curl_easy_setopt` / `curl_setopt` /
                        // `Nokogiri::XML` activate on a bare-leaf identifier
                        // match instead of firing conservatively on every
                        // positional arg.
                        if matches!(lang, "c" | "cpp" | "c++" | "php" | "ruby" | "rb") {
                            extract_const_macro_arg(cn, idx, code)
                        } else {
                            None
                        }
                    })
                },
                |kw| {
                    // For JS/TS, options-bearing args are passed as inline
                    // object literals (`fn(x, { evaluate: false })`) rather
                    // than language-level keyword arguments.  When the
                    // standard `keyword_argument`-walking extractor returns
                    // None, fall back to inspecting arg 1's object literal
                    // for a property named `kw`.  This lets gates like
                    // `_.template` consult `{ evaluate: false }` literally.
                    extract_const_keyword_arg(cn, kw, code).or_else(|| {
                        if matches!(lang, "javascript" | "typescript") {
                            extract_object_arg_property(cn, 1, kw, code)
                        } else {
                            None
                        }
                    })
                },
                |kw| {
                    has_keyword_arg(cn, kw, code)
                        || (matches!(lang, "javascript" | "typescript")
                            && has_object_arg_property(cn, 1, kw, code))
                },
            );

            if !matches.is_empty() {
                // Per-gate filter accumulation.  Each match contributes:
                //   * its label (added to `labels` so `resolve_sink_caps`
                //     downstream sees the union),
                //   * a `GateFilter` carrying that gate's specific
                //     `(label_caps, payload_args, destination_uses)` so
                //     the SSA sink scan can attribute taint per-cap.
                //
                // When a flat sink already matches, gate labels are deduped
                // so the same capability isn't attributed twice (once flat,
                // once gated).  Their `payload_args` still flow into
                // `sink_payload_args` so the gate's arg-position restriction
                // applies on top of the flat sink.
                let mut union_payload: Vec<usize> = Vec::new();
                for gm in &matches {
                    if has_sink_label {
                        if !labels.contains(&gm.label) {
                            labels.push(gm.label);
                        }
                    } else {
                        labels.push(gm.label);
                    }

                    let mut payload_vec: Vec<usize> =
                        if gm.payload_args == crate::labels::ALL_ARGS_PAYLOAD {
                            // Dynamic-activation sentinel: every positional arg is
                            // conservatively a payload.  Expand using the actual
                            // call arity so `collect_tainted_sink_values` checks
                            // each one.
                            let arity = extract_arg_uses(cn, code).len();
                            (0..arity).collect()
                        } else {
                            gm.payload_args.to_vec()
                        };

                    // Destination-aware gates: when the gate declares
                    // destination-bearing object fields and a payload-position
                    // arg is an object literal at call time, narrow sink-taint
                    // checks to identifiers under those fields.  Non-object
                    // arg forms return `None` from the extractor and the gate
                    // falls back to whole-arg positional filtering.
                    //
                    // The pair form preserves which object-literal field each
                    // ident was bound to (e.g. `body` vs `headers` vs `json`)
                    // so diag rendering can attribute `DATA_EXFIL` findings to
                    // a specific destination field.
                    let mut dest_uses: Option<Vec<String>> = None;
                    let mut dest_fields: Vec<String> = Vec::new();
                    if !gm.object_destination_fields.is_empty() {
                        let mut all_pairs: Vec<(String, String)> = Vec::new();
                        let mut had_object_match = false;
                        for &pos in gm.payload_args {
                            if let Some(pairs) = extract_destination_field_pairs(
                                cn,
                                pos,
                                gm.object_destination_fields,
                                code,
                            ) {
                                all_pairs.extend(pairs);
                                had_object_match = true;
                                break;
                            }
                        }

                        // Direct kwargs: languages where destination-bearing
                        // fields are passed as `keyword_argument` siblings of
                        // the positional args (Python `data=`, Ruby kwargs).
                        // SSA lowering folds kwarg idents into the implicit
                        // args group at index `arity`, so we expand
                        // `payload_vec` to include that position; the
                        // `destination_filter` then narrows to the kwarg
                        // ident's `var_name`.
                        let kwarg_pairs =
                            extract_destination_kwarg_pairs(cn, gm.object_destination_fields, code);
                        if !kwarg_pairs.is_empty() {
                            let arity = extract_arg_uses(cn, code).len();
                            if !payload_vec.contains(&arity) {
                                payload_vec.push(arity);
                            }
                            for pair in kwarg_pairs {
                                if !all_pairs.iter().any(|(_, v)| v == &pair.1) {
                                    all_pairs.push(pair);
                                }
                            }
                        }

                        if had_object_match || !all_pairs.is_empty() {
                            let (fields, vars): (Vec<String>, Vec<String>) =
                                all_pairs.into_iter().unzip();
                            dest_uses = Some(vars);
                            dest_fields = fields;
                        }
                    }

                    let label_caps = match gm.label {
                        crate::labels::DataLabel::Sink(c) => c,
                        _ => crate::labels::Cap::empty(),
                    };

                    for &p in &payload_vec {
                        if !union_payload.contains(&p) {
                            union_payload.push(p);
                        }
                    }
                    gate_filters.push(GateFilter {
                        label_caps,
                        payload_args: payload_vec,
                        destination_uses: dest_uses,
                        destination_fields: dest_fields,
                    });
                }
                if !union_payload.is_empty() {
                    sink_payload_args = Some(union_payload);
                }
                // Legacy single-gate path keeps `destination_uses` populated so
                // the SSA fast-path (one filter) continues to work without
                // consulting `gate_filters`.  When multiple gates match,
                // per-position filters live in `gate_filters` and the legacy
                // field is intentionally left `None`.
                if gate_filters.len() == 1 {
                    destination_uses = gate_filters[0].destination_uses.clone();
                }
            }
        }
    }

    // ── Inline shell-array sink synthesis ────────────────────────────────
    //
    // Recognise `[<shell>, "-c", <payload>]` (and `cmd /c <payload>`)
    // appearing as an argument to *any* call.  The shell-array shape itself
    // is the gate, regardless of callee, so this fires through user-defined
    // wrappers like `execInContainer(id, ["bash", "-c", `echo ${tainted}`])`
    // without needing per-wrapper summary annotations.  Only fires for JS/TS
    // because the array-literal grammar (`array` node) and shell-form usage
    // are JS/TS conventions; other languages use different shapes for
    // shell-exec wrappers.
    //
    // The inner array also covers Dockerode's
    // `container.exec({Cmd: [shell, "-c", payload]})`: the helper looks
    // inside object-literal args for shell-array values under any field.
    //
    // Existing FP carve-outs are preserved.  `["ls", "-la"]` doesn't match
    // (element 0 is not a known shell).  `untaintedArrayVariable` doesn't
    // match (variable, not literal).  `execSync(cmd, { env: process.env })`
    // doesn't match (string + object args, no shell-array literal).  When
    // the payload elements are constant strings the helper returns no
    // match, so a literal `["bash", "-c", "ls -la"]` doesn't fire either.
    if matches!(lang, "javascript" | "js" | "typescript" | "ts") {
        if let Some(cn) = call_ast.or_else(|| find_call_node_deep(ast, lang, 4)) {
            let shell_matches = extract_shell_array_payload_idents(cn, code);
            if !shell_matches.is_empty() {
                let shell_label = DataLabel::Sink(Cap::SHELL_ESCAPE);
                let already_has_shell_sink = labels.iter().any(|l| match l {
                    DataLabel::Sink(c) => c.contains(Cap::SHELL_ESCAPE),
                    _ => false,
                });
                if !already_has_shell_sink {
                    labels.push(shell_label);
                }

                let mut union_payload: Vec<usize> = sink_payload_args.clone().unwrap_or_default();
                for sm in shell_matches {
                    if !union_payload.contains(&sm.arg_position) {
                        union_payload.push(sm.arg_position);
                    }
                    gate_filters.push(GateFilter {
                        label_caps: Cap::SHELL_ESCAPE,
                        payload_args: vec![sm.arg_position],
                        destination_uses: Some(sm.payload_idents),
                        destination_fields: Vec::new(),
                    });
                }
                if !union_payload.is_empty() {
                    sink_payload_args = Some(union_payload);
                }
                // Legacy single-gate path: when this is the only gate filter,
                // populate the top-level destination_uses too so the SSA
                // fast-path stays consistent with the multi-gate behaviour.
                if gate_filters.len() == 1 {
                    destination_uses = gate_filters[0].destination_uses.clone();
                }
            }
        }
    }

    // Pattern-based sanitizer synthesis: recognise a Rust
    // `param.replace(LIT, LIT)[.replace(LIT, LIT)]*` chain that provably strips
    // path-traversal or HTML metacharacters.  The CFG collapses the whole
    // chain into a single call node, so detection must inspect the AST of
    // that node directly.  Only fires when no Sanitizer label already
    // classifies this node, existing label rules win.
    if lang == "rust" && !labels.iter().any(|l| matches!(l, DataLabel::Sanitizer(_))) {
        if let Some(cn) = call_ast {
            if cn.kind() == "call_expression" || cn.kind() == "method_call_expression" {
                if let Some(caps) = detect_rust_replace_chain_sanitizer(cn, code) {
                    labels.push(DataLabel::Sanitizer(caps));
                }
            }
        }
    }

    // Pattern-based sanitizer synthesis for Go's `strings.Replace` /
    // `strings.ReplaceAll`.  When the call's OLD literal contains a known
    // dangerous payload (shell metachars, path-traversal, HTML, SQL) and
    // the NEW literal does not reintroduce one, treat the call as a
    // Sanitizer over the matching caps.  Same precedence as the Rust
    // chain synthesis: explicit Sanitizer labels win, but otherwise the
    // synthesised label feeds the standard sanitizer pathway in the
    // taint engine.  Motivated by helpers like
    //   `func validate(s string) string { return strings.ReplaceAll(s, ";", "") }`
    // whose return is appended to a slice that later flows into
    // `exec.Command(slice[i])`.
    if lang == "go" && !labels.iter().any(|l| matches!(l, DataLabel::Sanitizer(_))) {
        if let Some(cn) = call_ast {
            if cn.kind() == "call_expression" {
                if let Some(caps) = detect_go_replace_call_sanitizer(cn, code) {
                    labels.push(DataLabel::Sanitizer(caps));
                }
            }
        }
    }

    // React JSX text-content auto-escape sanitizer synthesis.  When the
    // assignment / wrapper / return AST contains a `{expr}` interpolation as
    // a direct child of a `jsx_element` or `jsx_fragment` (NOT inside a
    // `jsx_attribute`), React's renderer escapes HTML metacharacters in the
    // interpolated value.  Tag the wrapping node `Sanitizer(HTML_ESCAPE)` so
    // SSA-level Assign / Call processing clears `HTML_ESCAPE` from the
    // resulting JSX value's caps.  Strictly additive — Source / Sink labels
    // already attached are preserved.  Already-present `Sanitizer(HTML_ESCAPE)`
    // is left untouched to avoid duplicate entries.
    if matches!(lang, "javascript" | "typescript" | "tsx")
        && matches!(
            lookup(lang, ast.kind()),
            Kind::CallWrapper | Kind::Assignment | Kind::Return
        )
        && !labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::HTML_ESCAPE)))
        && jsx_text_content_interp_present(ast, lang)
    {
        labels.push(DataLabel::Sanitizer(Cap::HTML_ESCAPE));
    }

    // Shape-based sanitizer synthesis for Ruby ActiveRecord query methods.
    // The static label table marks `where` / `order` / `pluck` / `group` /
    // `having` / `joins` as `Sink(SQL_QUERY)` because their string-interpolation
    // form (`Model.where("id = #{x}")`) is a real SQLi vector.  But the same
    // methods are intrinsically parameterised when arg 0 is a hash, symbol,
    // array, or non-interpolated string, Rails escapes the values.  Rather
    // than dropping the sink (which would lose the genuine TPs), synthesise
    // a same-node `Sanitizer(SQL_QUERY)` for the safe shapes; this clears
    // SQL taint at the call and reflexively dominates the sink, suppressing
    // both `taint-unsanitised-flow` and `cfg-unguarded-sink` for the safe
    // forms while leaving the dangerous ones to fire.
    //
    // Chained calls (`Model.where(...).preload(...).to_a`) collapse into a
    // single CFG node whose outer `call_ast` may be `to_a` (no args). The
    // shape inspection has to walk the receiver chain to reach the AR query
    // call itself, `ruby_chain_arg0_for_method` does that walk.
    if (lang == "ruby" || lang == "rb")
        && labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SQL_QUERY)))
        && !labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::SQL_QUERY)))
    {
        // Identify the matched AR query method from the callee `text`
        // (e.g. "Issue.where" → "where", "joins(:project).where" → "where").
        let leaf = text.rsplit(['.', ':']).next().unwrap_or(&text);
        const AR_QUERY_METHODS: &[&str] = &["where", "order", "group", "having", "joins", "pluck"];
        if AR_QUERY_METHODS.contains(&leaf) {
            // Try the outer call's arg 0 first (handles direct calls);
            // fall back to walking the receiver chain for collapsed
            // chained-call CFG nodes.
            let shape = call_ast
                .and_then(arg0_kind_and_interpolation)
                .or_else(|| ruby_chain_arg0_for_method(ast, &[leaf], code));
            if let Some((arg0_kind, has_interp)) = shape
                && crate::labels::ruby::ar_query_safe_shape(&text, &arg0_kind, has_interp)
            {
                labels.push(DataLabel::Sanitizer(Cap::SQL_QUERY));
            }
        }
    }

    // Shape-based sanitizer synthesis for Java JPA / JDBC parameterised
    // execute calls.  `executeUpdate` and `executeQuery` are labelled
    // `Sink(SQL_QUERY)` because the JDBC `Statement.executeUpdate(String)`
    // and `Statement.executeQuery(String)` overloads are real injection
    // sinks when given a concatenated SQL string.  But the same method
    // names on JPA `javax.persistence.Query` and JDBC `PreparedStatement`
    // are zero-arg, they execute SQL that was bound upstream by
    // `entityManager.createQuery(LITERAL)` / `connection.prepareStatement(LITERAL)`,
    // and any bind values went through `setParameter` / `setString`
    // (which the JDBC/JPA driver escapes).  Walk the receiver chain to
    // find the SQL-binding call and verify its arg 0 is a string literal;
    // if so, synthesise a same-node `Sanitizer(SQL_QUERY)` which
    // reflexively dominates the sink, suppressing both
    // `cfg-unguarded-sink` and `taint-unsanitised-flow` for the safe
    // chain shape while leaving `Statement.executeUpdate(concat)` and
    // `createQuery(concat)` to fire as real findings.
    if lang == "java"
        && labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SQL_QUERY)))
        && !labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::SQL_QUERY)))
    {
        let leaf = text.rsplit('.').next().unwrap_or(&text);
        if matches!(leaf, "executeUpdate" | "executeQuery") {
            // Outer call must be zero-arg (the prepared/parameterised
            // execute shape).  The N-arg overload `Statement.executeUpdate(SQL)`
            // is a real sink and must continue to fire.
            let outer_zero_arg = call_ast
                .and_then(|cn| cn.child_by_field_name("arguments"))
                .map(|args| {
                    let mut c = args.walk();
                    args.named_children(&mut c).count() == 0
                })
                .unwrap_or(false);
            if outer_zero_arg {
                // Walk the receiver chain to find a SQL-binding call
                // (`createQuery` / `createNativeQuery` / `prepareStatement`)
                // and require its arg 0 to be a string literal.  Anything
                // else (binary concat, identifier, method call) leaves
                // the sink in place, we cannot prove the SQL is
                // parameterised, so the structural finding stands.
                const JPA_BIND_METHODS: &[&str] = &[
                    "createQuery",
                    "createNativeQuery",
                    "createNamedQuery",
                    "prepareStatement",
                    "prepareCall",
                ];
                if let Some(call_node) = call_ast
                    && let Some(arg0_kind) =
                        java_chain_arg0_kind_for_method(call_node, JPA_BIND_METHODS, code)
                    && arg0_kind == "string_literal"
                {
                    labels.push(DataLabel::Sanitizer(Cap::SQL_QUERY));
                }
            }
        }
    }

    // Shape-based sanitizer synthesis for JS/TS ORM-accessor chains.
    // The static label table marks `db.query` / `connection.query` /
    // `pool.query` / `client.query` / `db.execute` as `Sink(SQL_QUERY)`
    // because the bare `connection.query("SELECT ..." + name)` form is a
    // real SQLi sink.  But the same `db.query` method on Strapi-style ORMs
    // takes a model UID literal and returns a chainable model accessor:
    // `strapi.db.query('admin::api-token').findOne({ where: whereParams })`.
    // The trailing `.findOne({...})` / `.findMany({...})` / `.create(...)`
    // calls are intrinsically parameterised, the actual SQL is generated
    // by the ORM, and the per-call values arrive through field-keyed object
    // literals that the ORM driver escapes.
    //
    // Recognition rule: when the CFG node's classified text reaches a sink
    // with `SQL_QUERY` cap, walk the receiver chain looking for an inner
    // `*.query(...)` / `*.execute(...)` whose arg 0 is a string literal
    // and whose result has at least one chained method call appended whose
    // name is in the ORM-accessor whitelist.  If both hold, synthesise a
    // same-node `Sanitizer(SQL_QUERY)` mirroring the Java JPA fix.  Bare
    // `connection.query("SELECT ...")` (no chained method) and
    // `db.query("UPDATE x SET y=" + name)` (non-literal arg 0) leave the
    // sink in place, both are genuine SQLi shapes.
    if (lang == "javascript"
        || lang == "js"
        || lang == "typescript"
        || lang == "ts"
        || lang == "tsx")
        && labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SQL_QUERY)))
        && !labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::SQL_QUERY)))
    {
        const QUERY_TARGETS: &[&str] = &["query", "execute"];
        // ORM-accessor methods that take object-literal args and return
        // promises of rows / row counts.  Promise methods (`then`, `catch`,
        // `finally`) deliberately excluded, they don't prove ORM shape.
        const ORM_CHAIN_METHODS: &[&str] = &[
            "findOne",
            "findMany",
            "findFirst",
            "findUnique",
            "findById",
            "find",
            "create",
            "createMany",
            "update",
            "updateMany",
            "upsert",
            "delete",
            "deleteMany",
            "count",
            "aggregate",
            "distinct",
            "save",
        ];
        // Fall back to a deeper walk (up to 4 levels) for await/return-
        // wrapped calls (e.g. `const x = await db.query(...).findOne(...)` ,
        // call sits at depth 3 inside lexical_declaration > variable_declarator
        // > await_expression > call_expression).
        let chain_call = call_ast.or_else(|| find_call_node_deep(ast, lang, 4));
        if let Some(call_node) = chain_call {
            // Outer method must be in the ORM whitelist *and* the chain must
            // have a deeper inner call to a `query`/`execute` whose arg 0 is
            // a string literal.  Both checks gate the synthesis.
            let outer_method = js_chain_outer_method_for_inner(call_node, QUERY_TARGETS, code);
            let outer_is_orm = outer_method
                .as_deref()
                .is_some_and(|m| ORM_CHAIN_METHODS.contains(&m));
            if outer_is_orm
                && let Some((arg0_kind, has_interp)) =
                    js_chain_arg0_kind_for_method(call_node, QUERY_TARGETS, code)
                && !has_interp
                && matches!(
                    arg0_kind.as_str(),
                    "string" | "string_fragment" | "template_string"
                )
            {
                labels.push(DataLabel::Sanitizer(Cap::SQL_QUERY));
            }
        }
    }

    let span = (ast.start_byte(), ast.end_byte());

    /* ── 3.  GRAPH INSERTION + DEBUG ──────────────────────────────────── */

    let (defines, uses, extra_defines, array_pattern_indices, rhs_array_elements) =
        def_use(ast, lang, code, extra);

    // Capture constant text for SSA constant propagation: when this node
    // defines a variable from a syntactic literal (no identifier uses),
    // extract the raw literal text from the AST.  Also capture the
    // argument of a const-return (`return []`) so the SSA const-return
    // synthesis can emit `Const(Some(text))` instead of `Const(None)`,
    // surfacing the literal text to downstream container-literal
    // detection.
    let const_text = if (defines.is_some() && uses.is_empty())
        || (kind == StmtKind::Return && uses.is_empty())
    {
        extract_literal_rhs(ast, lang, code)
    } else {
        None
    };

    let callee = if kind == StmtKind::Call || !labels.is_empty() {
        Some(text.clone())
    } else {
        None
    };

    // Extract condition metadata for If nodes.
    let (condition_text, condition_vars, condition_negated) = if kind == StmtKind::If {
        extract_condition_raw(ast, lang, code)
    } else {
        (None, Vec::new(), false)
    };

    // Extract per-argument identifiers for Call nodes.
    // Also extract for gated-sink nodes so payload-arg filtering works.
    let arg_uses = if kind == StmtKind::Call || sink_payload_args.is_some() {
        call_ast
            .map(|cn| extract_arg_uses(cn, code))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // String-literal values at each positional argument, parallel to
    // `arg_uses`.  Populated whenever there is a call AST so downstream
    // passes (static-map, symex, sink suppression) can consume literals
    // without re-accessing source bytes.
    let arg_string_literals = call_ast
        .map(|cn| extract_arg_string_literals(cn, code))
        .unwrap_or_default();

    // Extract keyword / named arguments for Call and gated-sink nodes.
    // Languages whose grammar doesn't produce `keyword_argument` / `named_argument`
    // children return an empty Vec, so this costs nothing for C/Java/Go/etc.
    let kwargs = if kind == StmtKind::Call || sink_payload_args.is_some() {
        call_ast
            .map(|cn| extract_kwargs(cn, code))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Check whether all arguments are syntactic literals (for taint sink suppression).
    let all_args_literal = if kind == StmtKind::Call {
        call_ast
            .map(|cn| has_only_literal_args(cn, code))
            .unwrap_or(false)
    } else {
        false
    };

    // Detect parameterized SQL queries: arg 0 is a string literal with
    // placeholder patterns ($1, ?, %s, :name) and >= 2 args present.
    // Uses a deeper recursive search than `call_ast` (which only goes 2
    // levels) to handle await-wrapped calls inside declarations.
    let parameterized_query = labels
        .iter()
        .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SQL_QUERY)))
        && call_ast
            .or_else(|| find_call_node_deep(ast, lang, 5))
            .is_some_and(|cn| is_parameterized_query_call(cn, code));

    // Extract per-argument inner call callees for interprocedural sanitizer resolution.
    // Also extracted for non-Call kinds (e.g. Assign whose RHS is a call like
    // `errs = append(errs, f.Close())`) so the inner-call-release-in-arg branch
    // in src/state/transfer.rs sees the closing call.
    let mut arg_callees = call_ast
        .map(|cn| extract_arg_callees(cn, lang, code))
        .unwrap_or_default();

    // For assignment sinks (including CallWrapper-wrapped assignments like
    // `element.innerHTML = clean(name)`), also extract the RHS callee.
    // This runs regardless of kind because a CallWrapper node may have
    // kind=Call (for the contained getElementById call) yet the actual
    // sink is the assignment to innerHTML.
    if !labels.is_empty() {
        let assign_node = if matches!(lookup(lang, ast.kind()), Kind::Assignment) {
            Some(ast)
        } else if matches!(lookup(lang, ast.kind()), Kind::CallWrapper) {
            let mut cursor = ast.walk();
            ast.children(&mut cursor)
                .find(|c| matches!(lookup(lang, c.kind()), Kind::Assignment))
        } else {
            None
        };
        if let Some(asgn) = assign_node
            && let Some(rhs) = asgn.child_by_field_name("right")
            && let Some(callee_name) = call_ident_of(rhs, lang, code)
        {
            arg_callees.push(Some(callee_name));
        }
    }

    // For method-style calls, extract the receiver identifier as a separate
    // channel on `CallMeta.receiver`.  The receiver is **not** prepended to
    // `arg_uses`: `arg_uses` contains positional-argument identifiers only,
    // and the receiver is carried as its own typed channel end-to-end
    // (SSA `SsaOp::Call.receiver`, summary `receiver_to_return`/`receiver_to_sink`).
    //
    // Two cases:
    // 1. Kind::CallMethod, native method call AST (Java method_invocation,
    //    Rust method_call_expression, Ruby call, PHP member_call_expression).
    //    Receiver is exposed via "object"/"receiver"/"scope" field on the call.
    // 2. Kind::CallFn whose function child is a member_expression (JS/TS) or
    //    attribute (Python).  These grammars model `obj.method(x)` as a plain
    //    call_expression/call with a dotted-name function child.  Without this
    //    branch the structured `receiver` stays `None` and type-qualified
    //    resolution loses its anchor.
    let receiver = if let Some(cn) = call_ast {
        match lookup(lang, cn.kind()) {
            Kind::CallMethod => {
                let recv_node = cn
                    .child_by_field_name("object")
                    .or_else(|| cn.child_by_field_name("receiver"))
                    .or_else(|| cn.child_by_field_name("scope"))
                    // Rust `method_call_expression` names the receiver "value".
                    .or_else(|| cn.child_by_field_name("value"));
                if let Some(rn) = recv_node
                    && matches!(rn.kind(), "identifier" | "variable_name")
                    && let Some(recv_text) = text_of(rn, code)
                {
                    Some(recv_text)
                } else if let Some(rn) = recv_node {
                    // Complex receiver (chain / field access / nested call).
                    // Drill through member/field/call nodes to the leftmost
                    // plain identifier so var_stacks lookup resolves the SSA
                    // value, which is what type-qualified resolution
                    // anchors on.  Falls back to `root_receiver_text` (which
                    // returns raw text like "conn.execute") only if drilling
                    // fails, preserving prior behavior for types we can't
                    // structurally reduce.
                    root_member_receiver(rn, code).or_else(|| root_receiver_text(cn, lang, code))
                } else {
                    None
                }
            }
            Kind::CallFn => {
                // JS/TS `obj.method(x)`: call_expression.function = member_expression.
                // Python `obj.method(x)`: call.function = attribute.
                // Rust `obj.method(x)`: call_expression.function = field_expression
                //    (field on `value`, not `object`, value can be another call
                //    for chained forms like `Connection::open(p).unwrap().execute(...)`).
                // Go `obj.method(x)`: call_expression.function = selector_expression
                //    (operand=receiver, field=method name).  Without this branch,
                //    `userDb.Raw(sql)` where `userDb` was bound from `gorm.Open(...)`
                //    loses its receiver channel, so type-qualified resolution can't
                //    rewrite `userDb.Raw` → `GormDb.Raw`.
                // Pull the receiver from the object/attribute-owner field.
                let func_child = cn.child_by_field_name("function");
                let recv_node = match func_child {
                    Some(fc) if fc.kind() == "member_expression" || fc.kind() == "attribute" => {
                        fc.child_by_field_name("object")
                    }
                    Some(fc) if fc.kind() == "field_expression" => fc.child_by_field_name("value"),
                    Some(fc) if fc.kind() == "selector_expression" => {
                        fc.child_by_field_name("operand")
                    }
                    _ => None,
                };
                if let Some(rn) = recv_node {
                    if matches!(rn.kind(), "identifier" | "variable_name" | "this" | "self") {
                        text_of(rn, code)
                    } else {
                        // Complex receiver (nested attribute, chained call, subscript).
                        // Drill to the leftmost plain identifier; when the chain is
                        // purely member_expression/attribute nodes, we want the base
                        // identifier (e.g. `request` for `request.args.get`).
                        root_member_receiver(rn, code)
                            .or_else(|| root_receiver_text(rn, lang, code))
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    };

    // Extract cast/type-assertion target type from AST node.
    let cast_target_type = match ast.kind() {
        // Java: (Type) expr
        "cast_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.kind(), "type_identifier" | "scoped_type_identifier"))
            .and_then(|n| text_of(n, code)),
        // TypeScript: expr as Type
        "as_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.kind(), "type_identifier" | "predefined_type"))
            .and_then(|n| text_of(n, code)),
        // TypeScript: <Type>expr (angle-bracket syntax)
        "type_assertion" => ast
            .child(0)
            .filter(|n| matches!(n.kind(), "type_identifier" | "predefined_type"))
            .and_then(|n| text_of(n, code)),
        // Go: expr.(Type)
        "type_assertion_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.kind(), "type_identifier" | "qualified_type"))
            .and_then(|n| text_of(n, code)),
        _ => None,
    };

    // RAII-managed resource detection: tag acquire nodes whose resources
    // are automatically cleaned up by language semantics (ownership/drop,
    // smart pointers).  Follows the same pattern as `managed_resource` for
    // Python `with` and Java try-with-resources.
    let is_raii_managed = is_raii_factory(lang, &text);

    // Ruby block form auto-close: `File.open(path) { |f| f.read }` ,
    // the block parameter receives the resource and Ruby guarantees close
    // at block exit.  If assigned (`f = File.open(p) { ... }`), the
    // variable holds the block's return value, not an open resource.
    let is_ruby_block_managed = lang == "ruby"
        && call_ast.is_some_and(|cn| {
            let mut c = cn.walk();
            cn.children(&mut c)
                .any(|ch| ch.kind() == "do_block" || ch.kind() == "block")
        });

    let string_prefix = extract_template_prefix(ast, lang, code)
        .or_else(|| call_ast.and_then(|cn| extract_template_prefix(cn, lang, code)));

    // Prefer the span of the call found by `find_classifiable_inner_call`
    // (deeper, classification-driven) over the one from `first_call_ident`
    // (shallower, text-override-driven).  Only record `callee_span` when it
    // actually narrows against `ast.span`, storing a redundant copy would
    // just bloat every labeled Call node.
    let callee_span = inner_callee_span.or(inner_text_span).filter(|s| *s != span);

    // Constructor detection: a `new X(...)` call carries different cap
    // semantics than a plain function call. The SSA Call transfer uses
    // this flag to narrow the constructed value's caps so out-of-process
    // side-effect bits (FILE_IO, FMT_STRING, URL_ENCODE, JSON_PARSE) on
    // the arguments don't survive into a wrapper-object instance.
    // Recognised forms:
    //   * JS/TS `new_expression`
    //   * Java/C++ `object_creation_expression`
    //   * PHP `object_creation_expression`
    let is_constructor = ast.kind() == "new_expression"
        || ast.kind() == "object_creation_expression"
        || call_ast
            .is_some_and(|cn| matches!(cn.kind(), "new_expression" | "object_creation_expression"));

    // Detect `Object.create(null)` so TypeFacts can tag the returned
    // SsaValue with `NullPrototypeObject` for flow-sensitive
    // prototype-pollution suppression.  Restricted to JS/TS where
    // `Object.create` is the idiomatic null-prototype constructor.
    let produces_null_proto = matches!(lang, "javascript" | "typescript")
        && call_ast.is_some_and(|cn| is_object_create_null_call(cn, code));

    let idx = g.add_node(NodeInfo {
        kind,
        call: CallMeta {
            callee,
            callee_text: None,
            outer_callee,
            callee_span,
            call_ordinal,
            arg_uses,
            receiver,
            sink_payload_args,
            kwargs,
            arg_string_literals,
            destination_uses,
            gate_filters,
            is_constructor,
            produces_null_proto,
        },
        taint: TaintMeta {
            labels,
            const_text,
            defines,
            uses,
            extra_defines,
            array_pattern_indices,
            rhs_array_elements,
        },
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        condition_text,
        condition_vars,
        condition_negated,
        all_args_literal,
        catch_param: false,
        arg_callees,
        cast_target_type,
        bin_op: extract_bin_op(ast, lang),
        bin_op_const: extract_bin_op_const(ast, lang, code),
        managed_resource: is_raii_managed || is_ruby_block_managed,
        in_defer: false,
        parameterized_query,
        string_prefix,
        is_eq_with_const: detect_eq_with_const(ast, lang),
        is_numeric_length_access: detect_numeric_length_access(ast, lang, code),
        member_field: detect_member_field_assignment(ast, code),
        rhs_is_function_literal: rhs_is_function_literal(ast, lang),
        is_await_forward: lookup(lang, ast.kind()) == Kind::AwaitForward,
    });

    debug!(
        target: "cfg",
        "node {} ← {:?} txt=`{}` span={:?} labels={:?}",
        idx.index(),
        kind,
        text,
        span,
        g[idx].taint.labels
    );
    idx
}

/// Add the same edge (of the same kind) from every node in `froms` to `to`.
#[inline]
pub(super) fn connect_all(g: &mut Cfg, froms: &[NodeIndex], to: NodeIndex, kind: EdgeKind) {
    for &f in froms {
        debug!(target: "cfg", "edge {} → {} ({:?})", f.index(), to.index(), kind);
        g.add_edge(f, to, kind);
    }
}

/// Pre-emit dedicated Source CFG nodes for call arguments that contain source
/// member expressions.
///
/// **Two-step API**, Source nodes must be created *before* the Call node so
/// they receive lower graph indices.  This is critical because the If handler
/// uses `NodeIndex::new(g.node_count())` to capture the first node built in a
/// branch and wires a True/False edge to it.  If the Source node has a lower
/// index than the Call node, the True edge lands on the Source node, and the
/// engine's redundant-Seq-edge skip logic correctly drops the parallel Seq
/// edge from the condition.  Without this ordering, the Seq edge would bypass
/// the auth-elevation transfer on the True edge and send Unauthed state into
/// the branch body.
///
/// True when `ast` is an assignment / declaration whose RHS is a
/// function or lambda literal, i.e. shapes like
///   * Go     `run := func() { ... }`
///   * JS/TS  `var run = function() { ... }` / `const run = () => ...`
///   * Python `run = lambda x: ...`
///   * Ruby   `run = ->() { ... }` / `run = proc { ... }`
///
/// Detected by walking the assignment's `right` / `value` field (or the
/// `init` field for declarators) and checking whether the resolved RHS
/// node classifies as `Kind::Function`.  Conservative: when the assignment
/// shape isn't recognised the function returns `false`.
///
/// Used by `push_node`'s RHS member-text fallback to suppress source/sink
/// label propagation from inside the literal's body up onto the outer
/// wrapper assignment.  The literal is processed as its own scope by
/// `collect_nested_function_nodes`.
fn rhs_is_function_literal(ast: Node, lang: &str) -> bool {
    use conditions::unwrap_parens;

    // Find the RHS node across the languages we support.  Most grammars
    // expose `right` (assignment_statement, assignment_expression,
    // short_var_declaration); JS / Java use `value` on
    // `variable_declarator` / `init_declarator`; Rust uses `value` on
    // `let_declaration`.
    let mut candidate = ast.child_by_field_name("right");

    if candidate.is_none() {
        // Walk one level into declarations whose direct child is the
        // declarator (variable_declaration → variable_declarator →
        // value), or expression-statement wrappers whose direct child is
        // an assignment_expression / assignment with a `right` field
        // (JS `expression_statement > assignment_expression`, Python
        // `expression_statement > assignment`).
        let mut cursor = ast.walk();
        for c in ast.children(&mut cursor) {
            if matches!(
                c.kind(),
                "variable_declarator" | "init_declarator" | "let_declaration"
            ) {
                candidate = c
                    .child_by_field_name("value")
                    .or_else(|| c.child_by_field_name("init"));
                if candidate.is_some() {
                    break;
                }
            } else if matches!(lookup(lang, c.kind()), Kind::Assignment) {
                candidate = c.child_by_field_name("right");
                if candidate.is_some() {
                    break;
                }
            }
        }
    }

    if candidate.is_none() {
        // Some grammars wrap the RHS in `expression_list` or similar.
        // Search recursively for a Kind::Function descendant of the
        // direct RHS-bearing fields.
        candidate = ast
            .child_by_field_name("value")
            .or_else(|| ast.child_by_field_name("init"));
    }

    let Some(rhs) = candidate else { return false };
    let rhs = unwrap_parens(rhs);
    if matches!(lookup(lang, rhs.kind()), Kind::Function) && rhs.child_count() > 0 {
        return true;
    }
    // Go's `expression_list` wrapping for short_var_declaration's RHS.
    if rhs.kind() == "expression_list" {
        let mut cursor = rhs.walk();
        for c in rhs.named_children(&mut cursor) {
            let c = unwrap_parens(c);
            if matches!(lookup(lang, c.kind()), Kind::Function) && c.child_count() > 0 {
                return true;
            }
        }
    }
    false
}

/// when `ast` is (or wraps) an assignment whose
/// LHS is a single subscript / index expression with a plain-identifier
/// receiver, emit a synthetic `__index_set__` Call node and return its
/// `NodeIndex`.  Returns `None` for non-subscript LHSs, multi-target
/// assignments, complex receivers, or when the RHS contains a call
/// (those still flow through the existing has_call_descendant path).
///
/// Gated on `pointer::is_enabled()` by the caller.
fn try_lower_subscript_write(
    ast: Node,
    preds: &[NodeIndex],
    g: &mut Cfg,
    lang: &str,
    code: &[u8],
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
) -> Option<NodeIndex> {
    // Locate the assignment node, `ast` may be the assignment itself
    // (Go `assignment_statement`) or a wrapper (`expression_statement`
    // containing JS `assignment_expression` / Python `assignment`).
    let assign_ast = if matches!(lookup(lang, ast.kind()), Kind::Assignment) {
        ast
    } else {
        let mut cursor = ast.walk();
        ast.children(&mut cursor)
            .find(|c| matches!(lookup(lang, c.kind()), Kind::Assignment))?
    };
    let lhs = assign_ast.child_by_field_name("left")?;
    if has_call_descendant(assign_ast, lang) {
        return None;
    }
    let subscript_node = subscript_lhs_node(lhs, lang)?;
    let (arr_text, idx_text) = subscript_components(subscript_node, code)?;
    let rhs = assign_ast.child_by_field_name("right")?;

    let mut rhs_uses: Vec<String> = Vec::new();
    collect_idents(rhs, code, &mut rhs_uses);
    let span = (ast.start_byte(), ast.end_byte());
    let ord = *call_ordinal;
    *call_ordinal += 1;
    let mut uses_all: Vec<String> = vec![arr_text.clone(), idx_text.clone()];
    uses_all.extend(rhs_uses.iter().cloned());

    // Prototype pollution sink classification on the synthetic
    // `__index_set__` node for JS/TS.  Tainted *key* in `obj[key] = val`
    // is the pollution channel (a `__proto__` / `constructor` literal flowing
    // through `key` mutates `Object.prototype` globally), so the gate's
    // payload arg list is `[0]` (the key only — the value at index 1 is
    // benign on its own).  Sanitizer recognition is structural (no taint
    // engine plumbing) and runs before label attachment, so suppressed
    // shapes never enter the SSA sink scan:
    //   * constant string key whose literal value is not in the dangerous
    //     set (`__proto__` / `constructor` / `prototype`),
    //   * receiver was assigned `Object.create(null)` in this function
    //     (no prototype chain to pollute),
    //   * the assignment is dominated by an `if` whose condition rejects
    //     dangerous keys with an early `return` / `throw` / `break`, or
    //     that allowlists the key against safe constants on its true arm.
    let mut pp_labels: smallvec::SmallVec<[DataLabel; 2]> = smallvec::SmallVec::new();
    let mut pp_payload_args: Option<Vec<usize>> = None;
    if matches!(lang, "javascript" | "typescript" | "js" | "ts")
        && !pp_should_suppress_index_set(assign_ast, subscript_node, &arr_text, &idx_text, code)
    {
        pp_labels.push(DataLabel::Sink(Cap::PROTOTYPE_POLLUTION));
        pp_payload_args = Some(vec![0]);
    }

    let n = g.add_node(NodeInfo {
        kind: StmtKind::Call,
        call: CallMeta {
            callee: Some("__index_set__".to_string()),
            receiver: Some(arr_text),
            arg_uses: vec![vec![idx_text], rhs_uses],
            call_ordinal: ord,
            sink_payload_args: pp_payload_args,
            ..Default::default()
        },
        taint: TaintMeta {
            labels: pp_labels,
            uses: uses_all,
            ..Default::default()
        },
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        ..Default::default()
    });
    connect_all(g, preds, n, EdgeKind::Seq);
    Some(n)
}

/// Spring MVC controller-return open-redirect recogniser.  Detects the
/// shape `return "redirect:" + tainted` (Java string concatenation) and
/// emits a synthetic `__spring_redirect__` Call sink with
/// `Sink(OPEN_REDIRECT)` so the existing taint pipeline propagates the
/// concatenated suffix through the OPEN_REDIRECT cap.  The synthetic
/// node sequences between `preds` and the eventual Return node.
///
/// Returns `Some(synthetic_idx)` when matched, otherwise `None`.
/// Java only — Spring's `redirect:` view-name convention has no
/// counterpart in the other supported languages, and matching the
/// literal across non-Spring code would over-fire.
fn try_lower_spring_redirect_return(
    ast: Node,
    preds: &[NodeIndex],
    g: &mut Cfg,
    lang: &str,
    code: &[u8],
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
) -> Option<NodeIndex> {
    if lang != "java" {
        return None;
    }
    // `return EXPR ;` — find the returned expression.  tree-sitter-java
    // wraps the value in a `return_statement` whose first named child
    // is the expression.
    let expr = ast.named_child(0)?;
    // Strip parentheses.
    let mut cur = expr;
    while cur.kind() == "parenthesized_expression" {
        cur = cur.named_child(0)?;
    }
    if cur.kind() != "binary_expression" {
        return None;
    }
    let op = cur.child_by_field_name("operator")?;
    let op_text = text_of(op, code)?;
    if op_text != "+" {
        return None;
    }
    // Walk leftmost descent through left-associated `+` chains so that
    // `"redirect:" + a + b` still matches (the AST nests as
    // `(("redirect:" + a) + b)`).
    let mut leftmost = cur;
    loop {
        let left = leftmost.child_by_field_name("left")?;
        let mut left_inner = left;
        while left_inner.kind() == "parenthesized_expression" {
            left_inner = left_inner.named_child(0)?;
        }
        if left_inner.kind() == "binary_expression" {
            let op_l = left_inner.child_by_field_name("operator")?;
            if text_of(op_l, code).as_deref() == Some("+") {
                leftmost = left_inner;
                continue;
            }
        }
        // `left_inner` is the leftmost atom — must be a string literal
        // whose constant value starts with `redirect:`.
        if !matches!(left_inner.kind(), "string_literal" | "string") {
            return None;
        }
        let lit = text_of(left_inner, code)?;
        if lit.len() < 2 {
            return None;
        }
        let inner = &lit[1..lit.len() - 1];
        if !inner.starts_with("redirect:") {
            return None;
        }
        break;
    }

    // Collect identifiers referenced anywhere in the original concat
    // expression — the tainted URL piece is one of them.  Receiver-style
    // method calls (`view.toString()`) are intentionally captured via
    // the bare identifier; precision improvements are deferred to the
    // SSA / abstract-string layer.
    let mut concat_uses: Vec<String> = Vec::new();
    collect_idents(cur, code, &mut concat_uses);
    if concat_uses.is_empty() {
        return None;
    }

    let span = (ast.start_byte(), ast.end_byte());
    let ord = *call_ordinal;
    *call_ordinal += 1;

    let mut labels: smallvec::SmallVec<[DataLabel; 2]> = smallvec::SmallVec::new();
    labels.push(DataLabel::Sink(Cap::OPEN_REDIRECT));

    let n = g.add_node(NodeInfo {
        kind: StmtKind::Call,
        call: CallMeta {
            callee: Some("__spring_redirect__".to_string()),
            arg_uses: vec![concat_uses.clone()],
            call_ordinal: ord,
            sink_payload_args: Some(vec![0]),
            ..Default::default()
        },
        taint: TaintMeta {
            labels,
            uses: concat_uses,
            ..Default::default()
        },
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        ..Default::default()
    });
    connect_all(g, preds, n, EdgeKind::Seq);
    Some(n)
}

/// React JSX `dangerouslySetInnerHTML={{ __html: x }}` recogniser.  Walks
/// `stmt_ast` for every `jsx_attribute` named `dangerouslySetInnerHTML` whose
/// value is a `jsx_expression → object → pair[key="__html"]` shape, and
/// synthesises a CFG call node `dangerouslySetInnerHTML(__html_value)` with
/// `Sink(HTML_ESCAPE)` and `sink_payload_args = [0]`.  The synthetic node's
/// span is the `__html` value subtree so finding-line attribution lands on
/// the payload, not the attribute name.
///
/// Returns the new frontier (synthetic exits) when one or more sinks were
/// emitted; otherwise returns `preds` unchanged.
///
/// Sanitizer-aware: when the `__html` value is a single call expression
/// whose callee classifies as a `Sanitizer`, the synthetic sink is still
/// emitted but its argument list is empty so no taint flows into it.
/// JS/TS only — JSX has no counterpart in the other supported languages.
#[allow(clippy::too_many_arguments)]
pub(super) fn try_lower_jsx_dangerous_html(
    stmt_ast: Node,
    preds: &[NodeIndex],
    g: &mut Cfg,
    lang: &str,
    code: &[u8],
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
) -> Vec<NodeIndex> {
    if !matches!(lang, "javascript" | "js" | "typescript" | "ts" | "tsx") {
        return preds.to_vec();
    }
    let mut attrs: Vec<Node> = Vec::new();
    collect_jsx_dangerous_html_attrs(stmt_ast, code, &mut attrs);
    if attrs.is_empty() {
        return preds.to_vec();
    }
    let extra = analysis_rules.map(|r| r.extra_labels.as_slice());
    let mut frontier: Vec<NodeIndex> = preds.to_vec();
    for attr in attrs {
        let Some(html_value) = jsx_extract_html_value(attr, code) else {
            continue;
        };
        let span = (html_value.start_byte(), html_value.end_byte());
        let ord = *call_ordinal;
        *call_ordinal += 1;

        // Sanitizer-aware: if the value subtree is a call to a known
        // sanitizer, emit the sink with no argument-side taint flow so the
        // synthetic site stays silent on already-sanitized payloads.
        let arg_uses_idents: Vec<String> = if jsx_value_is_sanitized(html_value, lang, code, extra)
        {
            Vec::new()
        } else {
            let mut idents: Vec<String> = Vec::new();
            collect_idents(html_value, code, &mut idents);
            idents
        };

        let mut labels: smallvec::SmallVec<[DataLabel; 2]> = smallvec::SmallVec::new();
        labels.push(DataLabel::Sink(Cap::HTML_ESCAPE));

        let n = g.add_node(NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some("dangerouslySetInnerHTML".to_string()),
                arg_uses: vec![arg_uses_idents.clone()],
                call_ordinal: ord,
                sink_payload_args: Some(vec![0]),
                ..Default::default()
            },
            taint: TaintMeta {
                labels,
                uses: arg_uses_idents,
                ..Default::default()
            },
            ast: AstMeta {
                span,
                enclosing_func: enclosing_func.map(|s| s.to_string()),
            },
            ..Default::default()
        });
        connect_all(g, &frontier, n, EdgeKind::Seq);
        frontier = vec![n];
    }
    frontier
}

/// Walk `root` collecting every `jsx_attribute` descendant whose name (via
/// the source bytes in `code`) equals `dangerouslySetInnerHTML`.
fn collect_jsx_dangerous_html_attrs<'a>(root: Node<'a>, code: &[u8], out: &mut Vec<Node<'a>>) {
    let mut stack: Vec<Node<'a>> = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "jsx_attribute" && jsx_attr_name_is(node, "dangerouslySetInnerHTML", code)
        {
            out.push(node);
            // Don't recurse into the attribute's own subtree; nested JSX
            // attributes inside the value are vanishingly rare and would
            // double-emit if the value contained another React element.
            continue;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// True when `root`'s subtree contains a `jsx_expression` whose direct
/// parent is a `jsx_element` or `jsx_fragment` (i.e. a `{expr}` text-content
/// interpolation between JSX tags).  React renders text content with HTML
/// metachar escaping, so any taint flowing through such an interpolation
/// has its `HTML_ESCAPE` cap cleared by the time the JSX value is rendered.
///
/// Bails at nested function-literal boundaries so JSX inside a closure body
/// (`const fn = () => <div>{bio}</div>`) does not falsely tag the outer
/// assignment — the closure's result only escapes when the closure is called
/// and rendered, which the outer assignment does not perform.
///
/// Excludes attribute interpolations (`<a href={url}/>`); React does
/// auto-escape attribute values as well, but the deferred-plan scope is
/// text-content only.  Widen if a fixture surfaces a pure-attribute FP.
fn jsx_text_content_interp_present(root: Node, lang: &str) -> bool {
    let mut stack: Vec<Node> = vec![root];
    while let Some(node) = stack.pop() {
        // Closure boundary: nested function bodies do not flow their JSX
        // result out through this assignment's value.
        if matches!(lookup(lang, node.kind()), Kind::Function) && node.id() != root.id() {
            continue;
        }
        if node.kind() == "jsx_expression"
            && let Some(parent) = node.parent()
            && matches!(parent.kind(), "jsx_element" | "jsx_fragment")
        {
            return true;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

/// Read the attribute name off a `jsx_attribute` node and compare against
/// `expected`.  Looks at the `name` field (or first named child) and reads
/// its UTF-8 text from `code`.
fn jsx_attr_name_is(attr: Node, expected: &str, code: &[u8]) -> bool {
    let name_node = match attr
        .child_by_field_name("name")
        .or_else(|| attr.named_child(0))
    {
        Some(n) => n,
        None => return false,
    };
    text_of(name_node, code)
        .map(|t| t == expected)
        .unwrap_or(false)
}

/// Resolve the `__html` value subtree of a JSX
/// `dangerouslySetInnerHTML={{ __html: <value> }}` attribute.  Returns the
/// AST node for `<value>` or `None` if the shape doesn't match.
fn jsx_extract_html_value<'a>(attr: Node<'a>, code: &[u8]) -> Option<Node<'a>> {
    let value = attr
        .child_by_field_name("value")
        .or_else(|| attr.named_child(1))?;
    // Strip the `{...}` wrapper.  tree-sitter exposes this as
    // `jsx_expression`; defensive against grammar variants by also
    // accepting the inner expression directly.
    let inner = if value.kind() == "jsx_expression" {
        let mut cur = value.walk();
        value
            .named_children(&mut cur)
            .find(|c| c.kind() != "comment")?
    } else {
        value
    };
    let object_kind = inner.kind();
    if !matches!(
        object_kind,
        "object" | "object_expression" | "object_literal"
    ) {
        return None;
    }
    let mut cur = inner.walk();
    for pair in inner.named_children(&mut cur) {
        if !matches!(
            pair.kind(),
            "pair" | "property" | "shorthand_property_identifier"
        ) {
            continue;
        }
        let key_node = pair
            .child_by_field_name("key")
            .or_else(|| pair.named_child(0));
        let val_node = pair
            .child_by_field_name("value")
            .or_else(|| pair.named_child(1));
        let (Some(k), Some(v)) = (key_node, val_node) else {
            continue;
        };
        let key_text = text_of(k, code).unwrap_or_default();
        // Strip surrounding quotes for `"__html"` / `'__html'` literal keys.
        let key_trim = key_text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
        if key_trim == "__html" {
            return Some(v);
        }
    }
    None
}

/// Returns true when `value_ast` is a call expression whose payload is
/// already routed through a `Sanitizer`.  Used to suppress argument-side
/// taint flow on the synthetic `dangerouslySetInnerHTML` sink.
///
/// Recognised shapes (JS/TS):
///
/// 1. Direct call: outer callee classifies as `Sanitizer` under the
///    rule set, e.g. `__html: DOMPurify.sanitize(input)`.
/// 2. Function-composition helpers — `pipe(input, sanitizeHtml, ...)`,
///    `compose(DOMPurify.sanitize, escapeHtml)(input)`, etc.  When the
///    outer callee leaf is one of `pipe` / `flow` / `compose` /
///    `flowRight` / `pipeWith` (covers fp-ts, Ramda, Lodash/fp,
///    Effect-TS), any argument whose text classifies as `Sanitizer`
///    is treated as the sanitization step.
///
/// Variable-bound sanitization (`const clean = sanitize(x); __html: clean`)
/// is handled by SSA value tracking on the bound identifier and does not
/// pass through this recogniser.
fn jsx_value_is_sanitized(
    value_ast: Node,
    lang: &str,
    code: &[u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> bool {
    let mut cur = value_ast;
    while cur.kind() == "parenthesized_expression" {
        let Some(inner) = cur.named_child(0) else {
            return false;
        };
        cur = inner;
    }
    if !matches!(cur.kind(), "call_expression" | "call") {
        return false;
    }
    let callee = match cur
        .child_by_field_name("function")
        .or_else(|| cur.child_by_field_name("name"))
    {
        Some(c) => c,
        None => return false,
    };
    let callee_text = match text_of(callee, code) {
        Some(t) => t,
        None => return false,
    };

    // 1. Direct sanitizer call.
    let labels = classify_all(lang, &callee_text, extra);
    if labels.iter().any(|l| matches!(l, DataLabel::Sanitizer(_))) {
        return true;
    }

    // 2. Function-composition helper.  Strip namespace qualifiers from the
    //    callee so `_.flow` / `R.pipe` / `fp.compose` all reduce to the
    //    leaf helper name.
    let leaf_callee = callee_text
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(callee_text.as_str());
    let is_compose_helper = matches!(
        leaf_callee,
        "pipe" | "flow" | "compose" | "flowRight" | "pipeWith"
    );
    if is_compose_helper {
        if let Some(args) = cur.child_by_field_name("arguments") {
            let mut walker = args.walk();
            for arg in args.named_children(&mut walker) {
                if matches!(arg.kind(), "comment") {
                    continue;
                }
                let Some(arg_text) = text_of(arg, code) else {
                    continue;
                };
                let arg_labels = classify_all(lang, &arg_text, extra);
                if arg_labels
                    .iter()
                    .any(|l| matches!(l, DataLabel::Sanitizer(_)))
                {
                    return true;
                }
            }
        }
    }

    false
}
///
/// Returns `true` when the assignment is provably safe and the
/// `Cap::PROTOTYPE_POLLUTION` sink label should be elided.  The three
/// CFG-layer recognised shapes are flow-insensitive AST patterns:
///
/// 1. Constant string key whose value is not one of the dangerous
///    keys (`__proto__`, `constructor`, `prototype`).  A literal-keyed
///    write cannot pollute even if the value is tainted.
/// 2. Reject pattern `if (idx === "__proto__" || idx === "constructor"
///    || idx === "prototype") <return/throw/break>` enclosing the
///    assignment.  The dangerous-key path terminates before reaching
///    the synthesised store.
/// 3. Allowlist pattern `if (idx === "name" || idx === "id") { obj[idx]
///    = v }`.  The assignment only executes when `idx` is one of a
///    small set of known-safe constants.
///
/// The null-prototype receiver suppression (`Object.create(null)`) is
/// handled flow-sensitively in the SSA taint engine via
/// `TypeKind::NullPrototypeObject`, since AST scans cannot honour
/// branch-local re-bindings or phi joins.
///
/// Conservative: any unrecognised shape returns `false` so the sink
/// label is attached and the SSA layer decides on taint reachability.
fn pp_should_suppress_index_set(
    assign_ast: Node,
    subscript_node: Node,
    _arr_text: &str,
    idx_text: &str,
    code: &[u8],
) -> bool {
    // 1. Constant-key fold.
    if let Some(idx_node) = subscript_node
        .child_by_field_name("index")
        .or_else(|| subscript_node.child_by_field_name("subscript"))
        .or_else(|| {
            let mut cur = subscript_node.walk();
            subscript_node.named_children(&mut cur).nth(1)
        })
    {
        if let Some(literal) = pp_string_literal_value(idx_node, code) {
            return !pp_is_dangerous_proto_key(&literal);
        }
    }

    // 2 + 3. Dominator-style guard ancestors (reject + allowlist).
    if pp_is_guarded_by_proto_check(assign_ast, idx_text, code) {
        return true;
    }

    false
}

/// Dangerous prototype-pollution key strings.  Matches the literal
/// values that JS engines treat as references into the prototype chain.
fn pp_is_dangerous_proto_key(s: &str) -> bool {
    matches!(s, "__proto__" | "constructor" | "prototype")
}

/// Extract the value of a JS/TS string literal node, stripping the
/// outer quote bytes (single, double, or backtick).  Returns `None`
/// for non-literal nodes, template literals containing interpolation,
/// or anything that doesn't resemble a single-segment string.
fn pp_string_literal_value(n: Node, code: &[u8]) -> Option<String> {
    let kind = n.kind();
    if !matches!(kind, "string" | "string_literal" | "template_string") {
        return None;
    }
    let raw = std::str::from_utf8(&code[n.start_byte()..n.end_byte()]).ok()?;
    if raw.len() < 2 {
        return None;
    }
    let bytes = raw.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !matches!(first, b'"' | b'\'' | b'`') || first != last {
        return None;
    }
    let inner = &raw[1..raw.len() - 1];
    // Reject template literals carrying `${...}` interpolation — we
    // can't fold those to a single concrete value.
    if first == b'`' && inner.contains("${") {
        return None;
    }
    Some(inner.to_string())
}

/// Walk up from the assignment node looking for two structural guard
/// shapes:
///
/// * **Reject pattern** — a *previous sibling* `if_statement` in any
///   enclosing block whose condition is `idx === DANGEROUS [|| …]` and
///   whose consequence terminates control flow (`return` / `throw` /
///   `break` / `continue`).  The dangerous-key path never reaches the
///   subsequent assignment.
/// * **Allowlist pattern** — an *ancestor* `if_statement` whose
///   condition is `idx === SAFE [|| …]` and through whose consequence
///   the descendant flows.  Only the safe-key arm reaches the
///   assignment.
///
/// Both shapes must compare against the same key variable as the
/// synthetic `__index_set__` node.  Stops at the enclosing function so
/// guards in an outer scope around a closure passed elsewhere don't
/// accidentally suppress inner assignments.
fn pp_is_guarded_by_proto_check(from: Node, idx_text: &str, code: &[u8]) -> bool {
    let mut cur = from;
    while let Some(parent) = cur.parent() {
        match parent.kind() {
            "function_declaration"
            | "function"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "generator_function_declaration"
            | "program"
            | "source_file" => return false,
            "if_statement" => {
                if let Some(cond) = parent.child_by_field_name("condition") {
                    let consequence = parent.child_by_field_name("consequence");
                    if let Some(verdict) =
                        pp_classify_proto_guard(cond, consequence, cur, idx_text, code)
                    {
                        return verdict;
                    }
                }
            }
            _ => {}
        }

        // Reject pattern: scan previous siblings in the parent block
        // for `if (idx === DANGEROUS [|| …]) { return; }` shapes that
        // dominate the assignment via early-return.
        let mut sibling_cursor = parent.walk();
        for sibling in parent.named_children(&mut sibling_cursor) {
            if sibling.start_byte() >= cur.start_byte() {
                break;
            }
            if sibling.kind() != "if_statement" {
                continue;
            }
            if pp_is_reject_pattern(sibling, idx_text, code) {
                return true;
            }
        }

        cur = parent;
    }
    false
}

/// True when `if_node` is `if (idx === DANGEROUS [|| idx === DANGEROUS]
/// …) { return; / throw …; / break; }` shaped — every disjunct
/// compares the named key variable to a dangerous prototype key, and
/// the consequence terminates control flow.
fn pp_is_reject_pattern(if_node: Node, idx_text: &str, code: &[u8]) -> bool {
    let Some(cond) = if_node.child_by_field_name("condition") else {
        return false;
    };
    let consequence = if_node.child_by_field_name("consequence");
    let clauses = pp_split_or_clauses(cond);
    if clauses.is_empty() {
        return false;
    }
    for clause in &clauses {
        let Some((var, lit)) = pp_extract_eq_compare(*clause, code) else {
            return false;
        };
        if var != idx_text || !pp_is_dangerous_proto_key(&lit) {
            return false;
        }
    }
    consequence.map(pp_block_terminates).unwrap_or(false)
}

/// Decide whether an enclosing `if` clause around an `__index_set__`
/// statement constitutes a prototype-pollution guard.
///
/// `cond` is the if's condition expression, `consequence` is the
/// optional consequence block, and `descendant` is the node on the
/// path from the if-statement down to the assignment (used to
/// distinguish "assignment lives inside the consequence" from
/// "assignment lives after the if").  `idx_text` is the textual key
/// variable used by the synthetic `__index_set__`.
///
/// Returns `Some(true)` to suppress, `Some(false)` to keep the gate
/// (e.g. an unrelated guard), and `None` when the if-statement is
/// not a recognised guard so the walker continues outward.
fn pp_classify_proto_guard(
    cond: Node,
    consequence: Option<Node>,
    descendant: Node,
    idx_text: &str,
    code: &[u8],
) -> Option<bool> {
    let cond_clauses = pp_split_or_clauses(cond);
    if cond_clauses.is_empty() {
        return None;
    }

    let mut all_against_idx = true;
    let mut all_dangerous = true;
    let mut all_safe = true;
    for clause in &cond_clauses {
        let (var, lit) = pp_extract_eq_compare(*clause, code)?;
        if var != idx_text {
            all_against_idx = false;
            break;
        }
        let dangerous = pp_is_dangerous_proto_key(&lit);
        if dangerous {
            all_safe = false;
        } else {
            all_dangerous = false;
        }
    }
    if !all_against_idx {
        return None;
    }

    let consequence_contains_descendant = consequence
        .map(|c| pp_subtree_contains(c, descendant))
        .unwrap_or(false);

    // Allowlist pattern: every clause is `idx === SAFE` and the
    // assignment lives inside the consequence (true arm).
    if all_safe && consequence_contains_descendant {
        return Some(true);
    }

    // Reject pattern: every clause is `idx === DANGEROUS` and the
    // consequence terminates control flow before reaching the
    // assignment.  Only suppress when the assignment is *outside* the
    // consequence (i.e., follows the if).
    if all_dangerous
        && !consequence_contains_descendant
        && consequence.map(pp_block_terminates).unwrap_or(false)
    {
        return Some(true);
    }

    None
}

/// True when `descendant` is identical to or transitively a child of
/// `root`.  Identity is checked via byte-range equality because
/// tree-sitter `Node` doesn't implement `Eq` directly.
fn pp_subtree_contains(root: Node, descendant: Node) -> bool {
    let dr = (descendant.start_byte(), descendant.end_byte());
    let rr = (root.start_byte(), root.end_byte());
    dr.0 >= rr.0 && dr.1 <= rr.1
}

/// True when `block` (typically an `if` consequence) terminates
/// control flow on every path: the last meaningful statement is a
/// return / throw / break / continue.  Conservative — falls back to
/// `false` for empty blocks or anything non-trivial.
fn pp_block_terminates(block: Node) -> bool {
    // Bare statement consequence (no braces): the if's consequence is
    // the terminator itself.
    if pp_is_terminator(block) {
        return true;
    }
    if !matches!(block.kind(), "statement_block" | "block") {
        return false;
    }
    let mut cursor = block.walk();
    let last_stmt = block.named_children(&mut cursor).last();
    match last_stmt {
        Some(s) => pp_is_terminator(s),
        None => false,
    }
}

/// True when `n` is a control-flow-ending statement: return / throw /
/// break / continue.
fn pp_is_terminator(n: Node) -> bool {
    matches!(
        n.kind(),
        "return_statement" | "throw_statement" | "break_statement" | "continue_statement"
    )
}

/// Split an expression by top-level `||` operators.  Returns the
/// individual disjunct sub-expressions.  Single (non-OR) expressions
/// yield a one-element vector.  Walks `binary_expression` nodes whose
/// `operator` field is `||` and recurses into both sides.
fn pp_split_or_clauses<'a>(expr: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    pp_collect_or_clauses(expr, &mut out);
    out
}

fn pp_collect_or_clauses<'a>(expr: Node<'a>, out: &mut Vec<Node<'a>>) {
    let stripped = pp_unwrap_paren(expr);
    if matches!(stripped.kind(), "binary_expression") {
        let op = stripped
            .child_by_field_name("operator")
            .map(|o| o.kind())
            .unwrap_or("");
        if op == "||" {
            if let Some(l) = stripped.child_by_field_name("left") {
                pp_collect_or_clauses(l, out);
            }
            if let Some(r) = stripped.child_by_field_name("right") {
                pp_collect_or_clauses(r, out);
            }
            return;
        }
    }
    out.push(stripped);
}

fn pp_unwrap_paren(n: Node) -> Node {
    let mut cur = n;
    while matches!(cur.kind(), "parenthesized_expression") {
        match cur.named_child(0) {
            Some(inner) => cur = inner,
            None => break,
        }
    }
    cur
}

/// Extract `(var_text, literal_value)` from an equality comparison
/// `var === "literal"` / `var == "literal"` (and reversed forms).
/// Returns `None` for any other shape.
fn pp_extract_eq_compare(expr: Node, code: &[u8]) -> Option<(String, String)> {
    let stripped = pp_unwrap_paren(expr);
    if !matches!(stripped.kind(), "binary_expression") {
        return None;
    }
    let op = stripped
        .child_by_field_name("operator")
        .map(|o| o.kind())
        .unwrap_or("");
    if !matches!(op, "===" | "==") {
        return None;
    }
    let left = stripped.child_by_field_name("left")?;
    let right = stripped.child_by_field_name("right")?;
    let left = pp_unwrap_paren(left);
    let right = pp_unwrap_paren(right);
    if let (Some(lv), Some(rs)) = (text_of(left, code), pp_string_literal_value(right, code)) {
        if matches!(left.kind(), "identifier" | "shorthand_property_identifier") {
            return Some((lv, rs));
        }
    }
    if let (Some(rv), Some(ls)) = (text_of(right, code), pp_string_literal_value(left, code)) {
        if matches!(right.kind(), "identifier" | "shorthand_property_identifier") {
            return Some((rv, ls));
        }
    }
    None
}

/// Step 1 (`pre_emit_arg_source_nodes`): scan the AST, create Source nodes,
/// wire them to `preds`, and return (effective_preds, synth_bindings,
/// uses_only_synth_names).
///
/// `synth_bindings` carry `(arg_pos, synth_name)` pairs that should be
/// appended to both the call's `arg_uses[arg_pos]` and its `taint.uses`.
/// `uses_only_synth_names` carry synth names that should *only* be
/// appended to `taint.uses`, used for chain-inner-arg sources where the
/// synth value is not a positional argument of the OUTER call but still
/// participates in the call's implicit dependency chain (e.g. `r.Body`
/// inside `json.NewDecoder(r.Body).Decode(emoji)`'s receiver).
///
/// Step 2 (`apply_arg_source_bindings`): after `push_node` creates the Call
/// node, add the synthetic variable names to its `arg_uses` and `uses`.
type PreEmitArgSourceResult = (SmallVec<[NodeIndex; 4]>, Vec<(usize, String)>, Vec<String>);

fn pre_emit_arg_source_nodes(
    g: &mut Cfg,
    ast: Node,
    lang: &str,
    code: &[u8],
    enclosing_func: Option<&str>,
    analysis_rules: Option<&LangAnalysisRules>,
    preds: &[NodeIndex],
) -> PreEmitArgSourceResult {
    let mut effective_preds: SmallVec<[NodeIndex; 4]> = SmallVec::from_slice(preds);
    let mut bindings: Vec<(usize, String)> = Vec::new();
    let mut uses_only: Vec<String> = Vec::new();

    let extra = analysis_rules.and_then(|r| {
        if r.extra_labels.is_empty() {
            None
        } else {
            Some(r.extra_labels.as_slice())
        }
    });

    let Some(call_ast) = find_call_node(ast, lang) else {
        return (effective_preds, bindings, uses_only);
    };
    let Some(args_node) = call_ast.child_by_field_name("arguments") else {
        return (effective_preds, bindings, uses_only);
    };

    // Collect children first (can't borrow cursor across mutable graph ops).
    let children: Vec<_> = {
        let mut cursor = args_node.walk();
        args_node.named_children(&mut cursor).collect()
    };

    // Bail on spread/splat/keyword arguments where positional mapping is unreliable.
    for child in &children {
        let k = child.kind();
        if k == "spread_element"
            || k == "dictionary_splat"
            || k == "list_splat"
            || k == "keyword_argument"
            || k == "splat_argument"
            || k == "hash_splat_argument"
            || k == "named_argument"
        {
            return (effective_preds, bindings, uses_only);
        }
    }

    let pointer_on = crate::pointer::is_enabled();

    for (pos, child) in children.iter().enumerate() {
        let src_label = first_member_label(*child, lang, code, extra);
        if let Some(DataLabel::Source(caps)) = src_label {
            // Use the *current* node count as a unique token, it equals the
            // index the new Source node will receive.
            let synth_name = format!("__nyx_src_{}_{}", g.node_count(), pos);
            let member_text = first_member_text(*child, code);
            let span = (child.start_byte(), child.end_byte());

            let mut src_labels: SmallVec<[DataLabel; 2]> = SmallVec::new();
            src_labels.push(DataLabel::Source(caps));

            let src_idx = g.add_node(NodeInfo {
                kind: StmtKind::Seq,
                call: CallMeta {
                    callee: member_text,
                    ..Default::default()
                },
                taint: TaintMeta {
                    labels: src_labels,
                    defines: Some(synth_name.clone()),
                    ..Default::default()
                },
                ast: AstMeta {
                    span,
                    enclosing_func: enclosing_func.map(|s| s.to_string()),
                },
                ..Default::default()
            });

            connect_all(g, &effective_preds, src_idx, EdgeKind::Seq);
            effective_preds.clear();
            effective_preds.push(src_idx);

            bindings.push((pos, synth_name));
            continue;
        }

        //pre-emit `__index_get__` Call nodes for
        // subscript / index-expression args when pointer analysis is
        // enabled.  This lets the W2/W4 container ELEM read hook fire
        // on the synth call, propagating must/may/caps from the cell
        // to the consuming sink call's argument.
        //
        // Gated on `pointer::is_enabled()` so the env-var=0 path keeps
        // CFG shapes bit-identical to today's output.  Only fires when
        // the array operand resolves to a plain identifier, see
        // `subscript_components` for the bail conditions.
        if pointer_on
            && is_subscript_kind(child.kind())
            && let Some((arr_text, idx_text)) = subscript_components(*child, code)
        {
            let synth_name = format!("__nyx_idxget_{}_{}", g.node_count(), pos);
            let span = (child.start_byte(), child.end_byte());

            let idx_node = g.add_node(NodeInfo {
                kind: StmtKind::Call,
                call: CallMeta {
                    callee: Some("__index_get__".to_string()),
                    receiver: Some(arr_text.clone()),
                    arg_uses: vec![vec![idx_text.clone()]],
                    ..Default::default()
                },
                taint: TaintMeta {
                    defines: Some(synth_name.clone()),
                    uses: vec![arr_text, idx_text],
                    ..Default::default()
                },
                ast: AstMeta {
                    span,
                    enclosing_func: enclosing_func.map(|s| s.to_string()),
                },
                ..Default::default()
            });

            connect_all(g, &effective_preds, idx_node, EdgeKind::Seq);
            effective_preds.clear();
            effective_preds.push(idx_node);

            bindings.push((pos, synth_name));
        }
    }

    // Chain-shape source pre-emission: walk the receiver chain of `call_ast`
    // and emit synth Source nodes for any source-labeled inner-call ARGs.
    //
    // This is what carries `r.Body` into the OUTER call's implicit-uses
    // group for shapes like `json.NewDecoder(r.Body).Decode(emoji)`, where
    // the outer callee text (`json.NewDecoder.Decode` after chain
    // normalisation) doesn't classify as a Source on its own.  Without
    // this, the writeback receiver-resolution path has nothing to read
    // from and the CVE-2024-31450 chain stays clean.
    //
    // Gated to Go and to writeback-shaped outer callees (`Decode` /
    // `Unmarshal`) because the synth-source emission is only useful when
    // a downstream writeback consumer reads from the chain's tainted
    // receiver, broader gating risks emitting synth sources whose taint
    // never propagates and whose presence trips Layer B AST-pattern
    // suppression on unrelated sinks (see
    // `tests/fixtures/real_world/go/taint/func_literal_capture.go`).
    // Synth names land in `uses_only` (not `bindings`) because they
    // don't correspond to a positional outer-call argument; they surface
    // only via `info.taint.uses`.
    let outer_method_is_writeback = call_ast
        .child_by_field_name("function")
        .or_else(|| call_ast.child_by_field_name("method"))
        .and_then(|f| {
            f.child_by_field_name("field")
                .or_else(|| f.child_by_field_name("property"))
                .or_else(|| f.child_by_field_name("name"))
        })
        .and_then(|n| text_of(n, code))
        .is_some_and(|name| name == "Decode" || name == "Unmarshal");
    if lang == "go" && outer_method_is_writeback {
        let mut inner_args: Vec<Node> = Vec::new();
        walk_chain_inner_call_args(call_ast, lang, &mut inner_args);
        for arg in inner_args {
            let k = arg.kind();
            // Mirror the splat/keyword bail from the outer-args pass.
            if k == "spread_element"
                || k == "dictionary_splat"
                || k == "list_splat"
                || k == "keyword_argument"
                || k == "splat_argument"
                || k == "hash_splat_argument"
                || k == "named_argument"
            {
                continue;
            }
            let src_label = first_member_label(arg, lang, code, extra);
            if let Some(DataLabel::Source(caps)) = src_label {
                let synth_name = format!("__nyx_chainsrc_{}_{}", g.node_count(), uses_only.len());
                let member_text = first_member_text(arg, code);
                let span = (arg.start_byte(), arg.end_byte());

                let mut src_labels: SmallVec<[DataLabel; 2]> = SmallVec::new();
                src_labels.push(DataLabel::Source(caps));

                let src_idx = g.add_node(NodeInfo {
                    kind: StmtKind::Seq,
                    call: CallMeta {
                        callee: member_text,
                        ..Default::default()
                    },
                    taint: TaintMeta {
                        labels: src_labels,
                        defines: Some(synth_name.clone()),
                        ..Default::default()
                    },
                    ast: AstMeta {
                        span,
                        enclosing_func: enclosing_func.map(|s| s.to_string()),
                    },
                    ..Default::default()
                });

                connect_all(g, &effective_preds, src_idx, EdgeKind::Seq);
                effective_preds.clear();
                effective_preds.push(src_idx);

                uses_only.push(synth_name);
            }
        }
    }

    (effective_preds, bindings, uses_only)
}

/// Step 2: wire synthetic variable names from pre-emitted Source nodes into
/// the Call node's `arg_uses` and `uses`.  `uses_only` synth names are
/// appended only to `taint.uses`, used for chain-inner-arg sources whose
/// synth value is not a positional outer-call argument.
fn apply_arg_source_bindings(
    g: &mut Cfg,
    call_node: NodeIndex,
    bindings: &[(usize, String)],
    uses_only: &[String],
) {
    for (pos, synth_name) in bindings {
        let arg_uses = &mut g[call_node].call.arg_uses;
        if *pos < arg_uses.len() {
            arg_uses[*pos].push(synth_name.clone());
        } else {
            while arg_uses.len() < *pos {
                arg_uses.push(vec![]);
            }
            arg_uses.push(vec![synth_name.clone()]);
        }
        g[call_node].taint.uses.push(synth_name.clone());
    }
    for synth_name in uses_only {
        g[call_node].taint.uses.push(synth_name.clone());
    }
}

// -------------------------------------------------------------------------
//    The recursive *work‑horse* that converts an AST node into a CFG slice.
//    Returns the set of *exit* nodes that need to be wired further.
// -------------------------------------------------------------------------
#[allow(clippy::too_many_arguments)]
pub(super) fn build_sub<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex], // predecessor frontier
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    summaries: &mut FuncSummaries,
    file_path: &str,
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
    break_targets: &mut Vec<NodeIndex>,
    continue_targets: &mut Vec<NodeIndex>,
    throw_targets: &mut Vec<NodeIndex>,
    bodies: &mut Vec<BodyCfg>,
    next_body_id: &mut u32,
    current_body_id: BodyId,
) -> Vec<NodeIndex> {
    match lookup(lang, ast.kind()) {
        // ─────────────────────────────────────────────────────────────────
        //  IF‑/ELSE: two branches that re‑merge afterwards
        // ─────────────────────────────────────────────────────────────────
        Kind::If => {
            // Some grammars (Go `if init; cond {}`, sibling C-style forms)
            // attach an init / "initializer" subtree that runs before the
            // condition.  Tree-sitter exposes it under the `initializer`
            // field.  Without lowering it, side-effecting calls in the
            // init (e.g. Owncast CVE-2024-31450's
            // `if err := json.NewDecoder(r.Body).Decode(emoji); err != nil`)
            // disappear from the CFG and downstream taint never sees the
            // call.  Languages that don't expose `initializer` here return
            // None and the post-init `preds` is bit-identical to the
            // pre-fix behaviour.  The init's exits become the predecessors
            // for the condition so its side effects are visible to both
            // branches.
            let init_exits_owned = ast.child_by_field_name("initializer").map(|init| {
                build_sub(
                    init,
                    preds,
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                )
            });
            let preds: &[NodeIndex] = match &init_exits_owned {
                Some(exits) => exits.as_slice(),
                None => preds,
            };
            // Check if condition contains a boolean operator for short-circuit decomposition.
            let cond_subtree = ast.child_by_field_name("condition").or_else(|| {
                // Rust `if_expression` uses positional children
                let mut cursor = ast.walk();
                ast.children(&mut cursor).find(|c| {
                    let k = c.kind();
                    !matches!(lookup(lang, k), Kind::Block | Kind::Trivia)
                        && k != "if"
                        && k != "else"
                        && k != "let"
                        && k != "{"
                        && k != "}"
                        && k != "("
                        && k != ")"
                })
            });

            let has_short_circuit = cond_subtree
                .map(|c| is_boolean_operator(unwrap_parens(c)).is_some())
                .unwrap_or(false);

            // Check for negation wrapping the entire condition (e.g. `!(a && b)`)
            //, if present, skip short-circuit decomposition (De Morgan out of scope).
            let has_short_circuit = has_short_circuit
                && cond_subtree.map_or(false, |c| {
                    let unwrapped = unwrap_parens(c);
                    !matches!(
                        unwrapped.kind(),
                        "unary_expression"
                            | "not_operator"
                            | "prefix_unary_expression"
                            | "unary_not"
                            | "unary_op_expression"
                    )
                });

            let is_unless = ast.kind() == "unless";

            // Determine true/false exit sets for wiring branches.
            let (true_exits, false_exits) = if has_short_circuit {
                let cond_ast = cond_subtree.unwrap();
                build_condition_chain(
                    cond_ast,
                    preds,
                    EdgeKind::Seq,
                    g,
                    lang,
                    code,
                    enclosing_func,
                )
            } else {
                // Single-node path (original behavior)
                let cond = push_node(
                    g,
                    StmtKind::If,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    0,
                    analysis_rules,
                );
                connect_all(g, preds, cond, EdgeKind::Seq);
                (vec![cond], vec![cond])
            };

            // For `unless`, swap: body runs when condition is false.
            let (then_preds, else_preds) = if is_unless {
                (&false_exits, &true_exits)
            } else {
                (&true_exits, &false_exits)
            };
            let (then_edge, else_edge) = if is_unless {
                (EdgeKind::False, EdgeKind::True)
            } else {
                (EdgeKind::True, EdgeKind::False)
            };

            // Locate then & else blocks using field-based lookup first,
            // then positional fallback (Rust uses positional blocks).
            let (then_block, else_block) = {
                let field_then = ast
                    .child_by_field_name("consequence")
                    .or_else(|| ast.child_by_field_name("body"));
                let field_else = ast.child_by_field_name("alternative");

                if field_then.is_some() || field_else.is_some() {
                    (field_then, field_else)
                } else {
                    // Fallback: positional block children (Rust `if_expression`)
                    let mut cursor = ast.walk();
                    let blocks: Vec<_> = ast
                        .children(&mut cursor)
                        .filter(|n| lookup(lang, n.kind()) == Kind::Block)
                        .collect();
                    (blocks.first().copied(), blocks.get(1).copied())
                }
            };

            // THEN branch
            let then_first_node = NodeIndex::new(g.node_count());
            let then_exits = if let Some(b) = then_block {
                let exits = build_sub(
                    b,
                    then_preds,
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                );
                // Add True/False edge from condition exit(s) to first node of then-branch.
                if then_first_node.index() < g.node_count() {
                    connect_all(g, then_preds, then_first_node, then_edge);
                } else if let Some(&first) = exits.first() {
                    connect_all(g, then_preds, first, then_edge);
                }
                exits
            } else {
                then_preds.to_vec()
            };

            // ELSE branch
            let else_first_node = NodeIndex::new(g.node_count());
            let else_exits = if let Some(b) = else_block {
                let exits = build_sub(
                    b,
                    else_preds,
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                );
                if else_first_node.index() < g.node_count() {
                    connect_all(g, else_preds, else_first_node, else_edge);
                } else if let Some(&first) = exits.first() {
                    connect_all(g, else_preds, first, else_edge);
                }
                exits
            } else {
                // No explicit else → create a synthetic pass-through node
                // for the false path.
                let pass = g.add_node(NodeInfo {
                    kind: StmtKind::Seq,
                    ast: AstMeta {
                        span: (ast.end_byte(), ast.end_byte()),
                        enclosing_func: enclosing_func.map(|s| s.to_string()),
                    },
                    ..Default::default()
                });
                connect_all(g, else_preds, pass, else_edge);
                vec![pass]
            };

            // Frontier = union of both branches
            then_exits.into_iter().chain(else_exits).collect()
        }

        Kind::InfiniteLoop => {
            // Synthetic header node
            let header = push_node(
                g,
                StmtKind::Loop,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, header, EdgeKind::Seq);

            // Fresh break/continue targets scoped to this loop
            let mut loop_breaks = Vec::new();
            let mut loop_continues = Vec::new();

            // The body is the single `block` child
            let body = match ast.child_by_field_name("body") {
                Some(b) => b,
                None => {
                    warn!(
                        "loop without body (error recovery?): kind={} byte={}",
                        ast.kind(),
                        ast.start_byte()
                    );
                    return vec![header];
                }
            };
            let body_exits = build_sub(
                body,
                &[header],
                g,
                lang,
                code,
                summaries,
                file_path,
                enclosing_func,
                call_ordinal,
                analysis_rules,
                &mut loop_breaks,
                &mut loop_continues,
                throw_targets,
                bodies,
                next_body_id,
                current_body_id,
            );

            // Back-edge from every linear exit to header
            for &e in &body_exits {
                connect_all(g, &[e], header, EdgeKind::Back);
            }
            // Wire continue targets as back edges to header
            for &c in &loop_continues {
                connect_all(g, &[c], header, EdgeKind::Back);
            }
            // Break targets become exits of the loop
            if loop_breaks.is_empty() {
                // No break → infinite loop; header is the only exit for
                // downstream code (fallthrough semantics)
                vec![header]
            } else {
                loop_breaks
            }
        }

        // ─────────────────────────────────────────────────────────────────
        //  WHILE / FOR: classic loop with a back edge.
        // ─────────────────────────────────────────────────────────────────
        Kind::While | Kind::For => {
            let header = push_node(
                g,
                StmtKind::Loop,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, header, EdgeKind::Seq);

            // Check for short-circuit condition
            let cond_subtree = ast.child_by_field_name("condition");
            let has_short_circuit = cond_subtree
                .map(|c| {
                    let unwrapped = unwrap_parens(c);
                    is_boolean_operator(unwrapped).is_some()
                        && !matches!(
                            unwrapped.kind(),
                            "unary_expression"
                                | "not_operator"
                                | "prefix_unary_expression"
                                | "unary_not"
                                | "unary_op_expression"
                        )
                })
                .unwrap_or(false);

            // Fresh break/continue targets scoped to this loop
            let mut loop_breaks = Vec::new();
            let mut loop_continues = Vec::new();

            // Body = first (and usually only) block child.  Tree-sitter error
            // recovery (or a fuzz mutation that truncates a `for`/`while`
            // header before the block) can leave a loop node with no body
            // child at all.  Match the InfiniteLoop arm above and degrade
            // gracefully instead of panicking — header alone is a valid CFG
            // skeleton for the malformed input.
            let body = match ast.child_by_field_name("body").or_else(|| {
                let mut c = ast.walk();
                ast.children(&mut c)
                    .find(|n| lookup(lang, n.kind()) == Kind::Block)
            }) {
                Some(b) => b,
                None => {
                    warn!(
                        "loop without body (error recovery?): kind={} byte={}",
                        ast.kind(),
                        ast.start_byte()
                    );
                    return vec![header];
                }
            };

            if has_short_circuit {
                let cond_ast = cond_subtree.unwrap();
                let (true_exits, false_exits) = build_condition_chain(
                    cond_ast,
                    &[header],
                    EdgeKind::Seq,
                    g,
                    lang,
                    code,
                    enclosing_func,
                );

                // Wire body from true_exits
                let body_first = NodeIndex::new(g.node_count());
                let body_exits = build_sub(
                    body,
                    &true_exits,
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    &mut loop_breaks,
                    &mut loop_continues,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                );
                // Add True edges from condition chain to body
                if body_first.index() < g.node_count() {
                    connect_all(g, &true_exits, body_first, EdgeKind::True);
                }

                // Back-edges go to header (not into the condition chain)
                for &e in &body_exits {
                    connect_all(g, &[e], header, EdgeKind::Back);
                }
                for &c in &loop_continues {
                    connect_all(g, &[c], header, EdgeKind::Back);
                }

                // Loop exits = false_exits + breaks
                let mut exits: Vec<NodeIndex> = false_exits;
                exits.extend(loop_breaks);
                exits
            } else {
                let body_exits = build_sub(
                    body,
                    &[header],
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    &mut loop_breaks,
                    &mut loop_continues,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                );

                // Back‑edge for every linear exit → header.
                for &e in &body_exits {
                    connect_all(g, &[e], header, EdgeKind::Back);
                }
                // Wire continue targets as back edges to header
                for &c in &loop_continues {
                    connect_all(g, &[c], header, EdgeKind::Back);
                }
                // Falling out of the loop = header’s false branch +
                // any break targets that exit the loop.
                let mut exits = vec![header];
                exits.extend(loop_breaks);
                exits
            }
        }

        // ─────────────────────────────────────────────────────────────────
        //  Control-flow sinks (return / break / continue).
        // ─────────────────────────────────────────────────────────────────
        Kind::Return => {
            if has_call_descendant(ast, lang) {
                // Return-call bug fix: emit a Call node BEFORE the Return so
                // that callee labels (source/sanitizer/sink) are applied.
                let ord = *call_ordinal;
                *call_ordinal += 1;
                let (effective_preds, src_bindings, src_uses_only) = pre_emit_arg_source_nodes(
                    g,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    analysis_rules,
                    preds,
                );
                let call_idx = push_node(
                    g,
                    StmtKind::Call,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    ord,
                    analysis_rules,
                );
                apply_arg_source_bindings(g, call_idx, &src_bindings, &src_uses_only);
                connect_all(g, &effective_preds, call_idx, EdgeKind::Seq);
                // React JSX `dangerouslySetInnerHTML={{__html: x}}` synthesis
                // (Phase 06): inserted between the wrapping Call (the inner
                // sanitizer / source call picked up by find_classifiable_inner_call)
                // and the Return so the synthetic sink fires on the
                // post-sanitization payload.
                let post_jsx = try_lower_jsx_dangerous_html(
                    ast,
                    &[call_idx],
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
                let ret = push_node(
                    g,
                    StmtKind::Return,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    0,
                    analysis_rules,
                );
                connect_all(g, &post_jsx, ret, EdgeKind::Seq);

                // Recurse into any function expressions nested inside the
                // returned call's arguments (e.g.
                // `return new Promise((res, rej) => { ... })`). Without this
                // the executor and any further inner callbacks are silently
                // swallowed and the gated sinks they contain become invisible
                // to classification. Mirrors the same recursion done by the
                // CallWrapper / CallFn arms. Motivated by CVE-2025-64430.
                //
                // Disconnect the placeholder Seq edge from the call after
                // build_sub returns; the inner body is independently
                // registered, so the outer call should flow straight to its
                // real successor (the Return below) without a phantom branch.
                let nested = collect_nested_function_nodes(ast, lang);
                for func_node in nested {
                    let placeholders = build_sub(
                        func_node,
                        &[call_idx],
                        g,
                        lang,
                        code,
                        summaries,
                        file_path,
                        enclosing_func,
                        call_ordinal,
                        analysis_rules,
                        break_targets,
                        continue_targets,
                        throw_targets,
                        bodies,
                        next_body_id,
                        current_body_id,
                    );
                    for ph in placeholders {
                        let to_remove: Vec<_> =
                            g.edges_connecting(call_idx, ph).map(|e| e.id()).collect();
                        for eid in to_remove {
                            g.remove_edge(eid);
                        }
                    }
                }

                Vec::new()
            } else {
                // Spring MVC `return "redirect:" + url` open-redirect
                // synthetic-sink emission.  When matched the synthetic
                // call sequences between `preds` and the Return node.
                let mut effective_preds: Vec<NodeIndex> = preds.to_vec();
                if let Some(synth) = try_lower_spring_redirect_return(
                    ast,
                    &effective_preds,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                ) {
                    effective_preds = vec![synth];
                }
                // React JSX `dangerouslySetInnerHTML={{__html: x}}` synthesis
                // (Phase 06) — fires when the JSX has no descendant call so
                // the wrapping Return arm reaches this branch.
                effective_preds = try_lower_jsx_dangerous_html(
                    ast,
                    &effective_preds,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
                let ret = push_node(
                    g,
                    StmtKind::Return,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    0,
                    analysis_rules,
                );
                connect_all(g, &effective_preds, ret, EdgeKind::Seq);
                Vec::new() // terminates this path
            }
        }
        Kind::Throw => {
            if has_call_descendant(ast, lang) {
                let ord = *call_ordinal;
                *call_ordinal += 1;
                let (effective_preds, src_bindings, src_uses_only) = pre_emit_arg_source_nodes(
                    g,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    analysis_rules,
                    preds,
                );
                let call_idx = push_node(
                    g,
                    StmtKind::Call,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    ord,
                    analysis_rules,
                );
                apply_arg_source_bindings(g, call_idx, &src_bindings, &src_uses_only);
                connect_all(g, &effective_preds, call_idx, EdgeKind::Seq);
                let ret = push_node(
                    g,
                    StmtKind::Throw,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    0,
                    analysis_rules,
                );
                connect_all(g, &[call_idx], ret, EdgeKind::Seq);
                throw_targets.push(ret);

                // Same nested-function recursion as the Return arm: a
                // `throw new Promise(() => { ... })` would otherwise lose
                // any inner gated sinks.  Disconnect the placeholder edge
                // (see Return arm comment).
                let nested = collect_nested_function_nodes(ast, lang);
                for func_node in nested {
                    let placeholders = build_sub(
                        func_node,
                        &[call_idx],
                        g,
                        lang,
                        code,
                        summaries,
                        file_path,
                        enclosing_func,
                        call_ordinal,
                        analysis_rules,
                        break_targets,
                        continue_targets,
                        throw_targets,
                        bodies,
                        next_body_id,
                        current_body_id,
                    );
                    for ph in placeholders {
                        let to_remove: Vec<_> =
                            g.edges_connecting(call_idx, ph).map(|e| e.id()).collect();
                        for eid in to_remove {
                            g.remove_edge(eid);
                        }
                    }
                }

                Vec::new()
            } else {
                let ret = push_node(
                    g,
                    StmtKind::Throw,
                    ast,
                    lang,
                    code,
                    enclosing_func,
                    0,
                    analysis_rules,
                );
                connect_all(g, preds, ret, EdgeKind::Seq);
                throw_targets.push(ret);
                Vec::new()
            }
        }
        Kind::Try => build_try(
            ast,
            preds,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        ),
        Kind::Break => {
            let brk = push_node(
                g,
                StmtKind::Break,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, brk, EdgeKind::Seq);
            break_targets.push(brk);
            Vec::new()
        }
        Kind::Continue => {
            let cont = push_node(
                g,
                StmtKind::Continue,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, preds, cont, EdgeKind::Seq);
            continue_targets.push(cont);
            Vec::new()
        }

        Kind::Switch => build_switch(
            ast,
            preds,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        ),

        // ─────────────────────────────────────────────────────────────────
        //  BLOCK: statements execute sequentially
        // ─────────────────────────────────────────────────────────────────
        Kind::SourceFile | Kind::Block => {
            // Ruby body_statement with rescue/ensure = implicit begin/rescue
            if lang == "ruby" && ast.kind() == "body_statement" {
                let mut check = ast.walk();
                if ast
                    .children(&mut check)
                    .any(|c| c.kind() == "rescue" || c.kind() == "ensure")
                {
                    return build_begin_rescue(
                        ast,
                        preds,
                        g,
                        lang,
                        code,
                        summaries,
                        file_path,
                        enclosing_func,
                        call_ordinal,
                        analysis_rules,
                        break_targets,
                        continue_targets,
                        throw_targets,
                        bodies,
                        next_body_id,
                        current_body_id,
                    );
                }
            }

            let mut cursor = ast.walk();
            let mut frontier = preds.to_vec();
            // With per-body CFGs, function definitions become placeholder
            // nodes that always have exactly one exit.  The frontier never
            // empties due to a function's internal return.  We still keep a
            // last-live fallback for preprocessor dangling-else edge cases.
            let mut last_live_frontier = preds.to_vec();
            let mut prev_was_preproc = false;
            for child in ast.children(&mut cursor) {
                let child_preds = if frontier.is_empty() && prev_was_preproc {
                    last_live_frontier.clone()
                } else {
                    frontier.clone()
                };

                // Go `defer`: record node count before recursing so we can
                // mark the deferred Call node(s) afterward.
                let is_defer = lang == "go" && child.kind() == "defer_statement";
                let defer_first_idx = if is_defer { g.node_count() } else { 0 };

                let child_exits = build_sub(
                    child,
                    &child_preds,
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                );

                // Mark only Call nodes inside the defer as deferred releases.
                if is_defer {
                    for raw in defer_first_idx..g.node_count() {
                        let idx = NodeIndex::new(raw);
                        if g[idx].kind == StmtKind::Call {
                            g[idx].in_defer = true;
                        }
                    }
                }

                let is_preproc = child.kind().starts_with("preproc_");
                if !child_exits.is_empty() {
                    last_live_frontier = child_exits.clone();
                }
                frontier = child_exits;
                prev_was_preproc = is_preproc;
            }
            frontier
        }

        // Function item – create a header and dive into its body
        Kind::Function => {
            // ── 1) Extract function name ──────────────────────────────────────
            // Lambda expressions don't have meaningful names; force the
            // synthetic anon name to avoid C++ lambdas picking up parameter
            // names via "declarator".
            let fn_name = if ast.kind() == "lambda_expression" {
                anon_fn_name(ast.start_byte())
            } else {
                ast.child_by_field_name("name")
                    .or_else(|| ast.child_by_field_name("declarator"))
                    .and_then(|n| {
                        let mut tmp = Vec::new();
                        collect_idents(n, code, &mut tmp);
                        tmp.into_iter().next()
                    })
                    .unwrap_or_else(|| anon_fn_name(ast.start_byte()))
            };

            // When the grammar-level name is anonymous, try to derive a binding
            // name from the surrounding declaration or assignment. This lets
            // `var h = function(x){...}` / `this.run = () => {...}` participate
            // in callback resolution, callers referencing `h` or `run` can
            // find the body via `resolve_local_func_key` and intra-file calls
            // like `h()` can resolve to the anonymous body's summary. Without
            // this, the body is keyed with the synthetic anon name and there
            // is no path from the variable identifier to the body.
            let fn_name = if is_anon_fn_name(&fn_name) {
                derive_anon_fn_name_from_context(ast, lang, code).unwrap_or(fn_name)
            } else {
                fn_name
            };

            let is_anon = is_anon_fn_name(&fn_name);
            let param_meta = extract_param_meta(ast, lang, code);
            let param_count = param_meta.len();
            let param_names: Vec<String> = param_meta.iter().map(|(n, _, _)| n.clone()).collect();
            let param_types: Vec<Option<crate::ssa::type_facts::TypeKind>> =
                param_meta.iter().map(|(_, t, _)| t.clone()).collect();
            let param_destructured_fields: Vec<Vec<String>> = param_meta
                .iter()
                .map(|(_, _, siblings)| siblings.clone())
                .collect();

            // ── 1b) Compute identity discriminators ───────────────────────────
            let (fn_container, fn_kind) =
                compute_container_and_kind(ast, ast.kind(), &fn_name, code);
            // Disambiguator: depth-first preorder index of this function node
            // within the file.  Always populated so two same-name, same-
            // container definitions never collide (e.g. duplicate defs in a
            // file, overload-like patterns, nested defs with identical names
            // in sibling scopes).  Stable against unrelated edits above the
            // function.  Falls back to the start byte when the DFS-index
            // map is absent (tests bypassing build_cfg).
            let fn_disambig: Option<u32> =
                Some(fn_dfs_index(ast.start_byte()).unwrap_or(ast.start_byte() as u32));

            // ── 2) Create a separate body graph for this function ─────────────
            let (mut fn_graph, fn_entry, fn_exit) =
                create_body_graph(ast.start_byte(), ast.end_byte(), Some(&fn_name));

            let body_ast = match ast.child_by_field_name("body").or_else(|| {
                let mut c = ast.walk();
                ast.children(&mut c)
                    .find(|n| matches!(lookup(lang, n.kind()), Kind::Block | Kind::SourceFile))
            }) {
                Some(b) => b,
                None => {
                    warn!(
                        "fn without body (forward decl / abstract / error recovery): kind={} name=’{}’",
                        ast.kind(),
                        fn_name
                    );
                    // Insert placeholder in parent graph and skip body processing
                    let placeholder = g.add_node(make_empty_node_info(
                        StmtKind::Seq,
                        (ast.start_byte(), ast.end_byte()),
                        enclosing_func,
                    ));
                    connect_all(g, preds, placeholder, EdgeKind::Seq);
                    return vec![placeholder];
                }
            };

            // Allocate a BodyId for this function
            let fn_body_id = BodyId(*next_body_id);
            *next_body_id += 1;

            let entry_preds = inject_framework_param_sources(
                ast,
                code,
                analysis_rules,
                &mut fn_graph,
                fn_entry,
                Some(&fn_name),
            );

            let mut fn_call_ordinal: u32 = 0;
            let mut fn_breaks = Vec::new();
            let mut fn_continues = Vec::new();
            let mut fn_throws = Vec::new();
            let body_exits = build_sub(
                body_ast,
                &entry_preds,
                &mut fn_graph,
                lang,
                code,
                summaries,
                file_path,
                Some(&fn_name),
                &mut fn_call_ordinal,
                analysis_rules,
                &mut fn_breaks,
                &mut fn_continues,
                &mut fn_throws,
                bodies,
                next_body_id,
                fn_body_id,
            );

            // ── 3) Wire exits to Exit node ────────────────────────────────────
            for &b in &body_exits {
                connect_all(&mut fn_graph, &[b], fn_exit, EdgeKind::Seq);
            }
            // Wire internal Return/Throw nodes to Exit (both terminate this body)
            for idx in fn_graph.node_indices().collect::<Vec<_>>() {
                if matches!(fn_graph[idx].kind, StmtKind::Return | StmtKind::Throw)
                    && idx != fn_exit
                    && !fn_graph.contains_edge(idx, fn_exit)
                {
                    connect_all(&mut fn_graph, &[idx], fn_exit, EdgeKind::Seq);
                }
            }

            // ── 4) Light-weight dataflow on the body graph ────────────────────
            let mut var_taint = HashMap::<String, Cap>::new();
            let mut node_bits = HashMap::<NodeIndex, Cap>::new();
            let mut fn_src_bits = Cap::empty();
            let mut fn_sani_bits = Cap::empty();
            let mut fn_sink_bits = Cap::empty();
            let mut callees = Vec::<crate::summary::CalleeSite>::new();
            let mut tainted_sink_params: Vec<usize> = Vec::new();

            for idx in fn_graph.node_indices() {
                let info = &fn_graph[idx];
                if let Some(callee) = &info.call.callee {
                    let site = build_callee_site(callee, info, lang);
                    // Dedup by (name, arity, receiver, qualifier, ordinal).  A
                    // single function may legitimately contain multiple distinct
                    // calls to the same callee (e.g. different ordinals or
                    // different receivers); all of those are kept.
                    if !callees.iter().any(|c| {
                        c.name == site.name
                            && c.arity == site.arity
                            && c.receiver == site.receiver
                            && c.qualifier == site.qualifier
                            && c.ordinal == site.ordinal
                    }) {
                        callees.push(site);
                    }
                }
                for lbl in &info.taint.labels {
                    match *lbl {
                        DataLabel::Source(bits) => fn_src_bits |= bits,
                        DataLabel::Sanitizer(bits) => fn_sani_bits |= bits,
                        DataLabel::Sink(bits) => {
                            fn_sink_bits |= bits;
                            for u in &info.taint.uses {
                                if let Some(pos) = param_names.iter().position(|p| p == u)
                                    && !tainted_sink_params.contains(&pos)
                                {
                                    tainted_sink_params.push(pos);
                                }
                            }
                        }
                    }
                }
                let mut in_bits = Cap::empty();
                for u in &info.taint.uses {
                    if let Some(b) = var_taint.get(u) {
                        in_bits |= *b;
                    }
                }
                let mut out_bits = in_bits;
                for lab in &info.taint.labels {
                    match *lab {
                        DataLabel::Source(bits) => out_bits |= bits,
                        DataLabel::Sanitizer(bits) => out_bits &= !bits,
                        DataLabel::Sink(_) => {}
                    }
                }
                if let Some(def) = &info.taint.defines {
                    if out_bits.is_empty() {
                        var_taint.remove(def);
                    } else {
                        var_taint.insert(def.clone(), out_bits);
                    }
                }
                node_bits.insert(idx, out_bits);
            }
            for (&idx, &bits) in &node_bits {
                if fn_graph[idx].kind == StmtKind::Return {
                    fn_src_bits |= bits;
                }
            }
            for &pred in &body_exits {
                if let Some(&bits) = node_bits.get(&pred) {
                    fn_src_bits |= bits;
                }
            }

            // ── propagating_params ────────────────────────────────────────────
            let propagating_params = {
                let mut params = Vec::new();
                for (i, pname) in param_names.iter().enumerate() {
                    let mut flows = false;
                    for &idx in node_bits.keys() {
                        if fn_graph[idx].kind == StmtKind::Return {
                            for u in &fn_graph[idx].taint.uses {
                                if u == pname {
                                    flows = true;
                                }
                                if let Some(bits) = var_taint.get(u)
                                    && !bits.is_empty()
                                    && var_taint.contains_key(pname)
                                {
                                    flows = true;
                                }
                            }
                        }
                    }
                    if !flows {
                        for &exit_pred in &body_exits {
                            let info = &fn_graph[exit_pred];
                            for u in &info.taint.uses {
                                if u == pname {
                                    flows = true;
                                }
                            }
                            if let Some(def) = &info.taint.defines
                                && def == pname
                            {
                                flows = true;
                            }
                        }
                    }
                    if flows {
                        params.push(i);
                    }
                }
                params
            };

            tainted_sink_params.sort_unstable();
            tainted_sink_params.dedup();

            // ── 5) Store summary (entry/exit are body-local) ──────────────────
            let key = FuncKey {
                lang: Lang::from_slug(lang).unwrap_or(Lang::Rust),
                namespace: file_path.to_owned(),
                container: fn_container.clone(),
                name: fn_name.clone(),
                arity: Some(param_count),
                disambig: fn_disambig,
                kind: fn_kind,
            };
            let body_func_key = key.clone();
            summaries.insert(
                key,
                LocalFuncSummary {
                    entry: fn_entry,
                    exit: fn_exit,
                    source_caps: fn_src_bits,
                    sanitizer_caps: fn_sani_bits,
                    sink_caps: fn_sink_bits,
                    param_count,
                    param_names: param_names.clone(),
                    propagating_params,
                    tainted_sink_params,
                    callees,
                    container: fn_container,
                    disambig: fn_disambig,
                    kind: fn_kind,
                },
            );

            // ── 6) Push BodyCfg ───────────────────────────────────────────────
            let auth_decorators = extract_auth_decorators(ast, lang, code);
            let route_captures = extract_route_path_captures(ast, lang, code);
            let param_route_capture: Vec<bool> = if route_captures.is_empty() {
                vec![false; param_names.len()]
            } else {
                param_names
                    .iter()
                    .map(|n| {
                        let lc = n.to_ascii_lowercase();
                        route_captures.iter().any(|c| c == &lc)
                    })
                    .collect()
            };
            bodies.push(BodyCfg {
                meta: BodyMeta {
                    id: fn_body_id,
                    kind: if is_anon {
                        BodyKind::AnonymousFunction
                    } else {
                        BodyKind::NamedFunction
                    },
                    name: if is_anon { None } else { Some(fn_name.clone()) },
                    params: param_names,
                    param_types,
                    param_destructured_fields,
                    param_count,
                    span: (ast.start_byte(), ast.end_byte()),
                    parent_body_id: Some(current_body_id),
                    func_key: Some(body_func_key),
                    auth_decorators,
                    param_route_capture,
                },
                graph: fn_graph,
                entry: fn_entry,
                exit: fn_exit,
            });

            // ── 7) Insert placeholder in parent graph ─────────────────────────
            // Declaration-marker only: no defines, uses, callee, or labels.
            let placeholder = g.add_node(make_empty_node_info(
                StmtKind::Seq,
                (ast.start_byte(), ast.end_byte()),
                enclosing_func,
            ));
            connect_all(g, preds, placeholder, EdgeKind::Seq);

            vec![placeholder]
        }

        // Statements that **may** contain a call ---------------------------------
        Kind::CallWrapper => {
            let mut cursor = ast.walk();

            // Recurse into divergent control-flow constructs nested inside
            // an expression-statement wrapper.  Rust's `expression_statement`
            // wraps `return_expression` / `break_expression` /
            // `continue_expression`; without this delegation the wrapper
            // would lower the return as a plain `StmtKind::Call`, losing
            // the return semantics and letting fall-through Seq edges
            // survive into the SSA terminator (the OR-chain rejection-arm
            // defect, see `or_chain_rejection_block_terminates_with_return`).
            if let Some(inner) = ast.children(&mut cursor).find(|c| {
                matches!(
                    lookup(lang, c.kind()),
                    Kind::InfiniteLoop
                        | Kind::While
                        | Kind::For
                        | Kind::If
                        | Kind::Return
                        | Kind::Throw
                        | Kind::Break
                        | Kind::Continue
                )
            }) {
                return build_sub(
                    inner,
                    preds,
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                );
            }

            // JS/TS ternary-RHS split: `var x = c ? a : b;` and
            // `obj.prop = c ? a : b;` lower to a real diamond CFG so the
            // condition is control-flow (not a data-flow `uses` entry).
            if matches!(lang, "javascript" | "typescript" | "tsx")
                && let Some((lhs_ast, ternary_ast)) = find_ternary_rhs_wrapper(ast)
            {
                let (lhs_text, lhs_labels) =
                    classify_ternary_lhs(lhs_ast, lang, code, analysis_rules);
                return build_ternary_diamond(
                    lhs_text,
                    lhs_labels,
                    ternary_ast,
                    preds,
                    EdgeKind::Seq,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
            }

            //subscript-write lowering when the
            // CallWrapper's inner expression is `arr[i] = v` (JS/TS,
            // Python).  See `try_lower_subscript_write` for shape +
            // bail matrix.
            if crate::pointer::is_enabled()
                && let Some(n) = try_lower_subscript_write(
                    ast,
                    preds,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                )
            {
                return vec![n];
            }

            let has_call = has_call_descendant(ast, lang);

            let kind = if has_call {
                StmtKind::Call
            } else {
                StmtKind::Seq
            };
            let ord = if kind == StmtKind::Call {
                let o = *call_ordinal;
                *call_ordinal += 1;
                o
            } else {
                0
            };

            // Pre-emit Source nodes for call arguments containing source
            // member expressions (e.g. `req.body.returnTo` inside
            // `res.redirect(req.body.returnTo)`).  Created BEFORE the Call
            // node so they get lower indices, see doc comment on
            // `pre_emit_arg_source_nodes` for why this ordering matters.
            let (effective_preds, src_bindings, src_uses_only) = if kind == StmtKind::Call {
                pre_emit_arg_source_nodes(g, ast, lang, code, enclosing_func, analysis_rules, preds)
            } else {
                (SmallVec::from_slice(preds), Vec::new(), Vec::new())
            };

            let node = push_node(
                g,
                kind,
                ast,
                lang,
                code,
                enclosing_func,
                ord,
                analysis_rules,
            );
            apply_arg_source_bindings(g, node, &src_bindings, &src_uses_only);

            // Python `with_item`: acquisition inside a context manager.
            // Only mark if this is actually an acquisition (Call + defines).
            if ast.kind() == "with_item"
                && g[node].kind == StmtKind::Call
                && g[node].taint.defines.is_some()
            {
                g[node].managed_resource = true;
            }

            connect_all(g, &effective_preds, node, EdgeKind::Seq);

            // React JSX `dangerouslySetInnerHTML={{__html: x}}` synthesis
            // (Phase 06): chained after the wrapper Call/Seq for cases like
            // `<div .../>;` (expression_statement) where the JSX appears as
            // a top-level expression statement.  No-op when the wrapper has
            // no matching JSX descendant.
            let post_jsx_frontier = try_lower_jsx_dangerous_html(
                ast,
                &[node],
                g,
                lang,
                code,
                enclosing_func,
                call_ordinal,
                analysis_rules,
            );

            // If the callee is a configured terminator, treat as a dead end
            if kind == StmtKind::Call
                && let Some(callee) = &g[node].call.callee
                && is_configured_terminator(callee, analysis_rules)
            {
                return Vec::new();
            }

            // Recurse into any function expressions nested in arguments
            // (e.g. `app.get('/path', function(req, res) { ... })`)
            // so that they get proper function summaries.  The build_sub
            // invocation registers the inner body but also adds a
            // Seq-edge `node → placeholder` from the inner Kind::Function
            // arm.  That phantom successor turns the outer call into a
            // 2-successor branch with an empty Return(None) leg, which
            // breaks `validated_params_to_return` summary extraction
            // (CVE-2026-25544).  Disconnect the spurious edge after
            // build_sub returns; the inner body is still reachable to
            // closure-capture passes via `parent_body_id` metadata.
            let nested = collect_nested_function_nodes(ast, lang);
            for func_node in nested {
                let placeholders = build_sub(
                    func_node,
                    &[node],
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                );
                for ph in placeholders {
                    let to_remove: Vec<_> = g.edges_connecting(node, ph).map(|e| e.id()).collect();
                    for eid in to_remove {
                        g.remove_edge(eid);
                    }
                }
            }

            // Rust match-guard synthesis: `let <name> = match <scrutinee> { <arm> if <guard> => .., ... }`
            // collapses to this single Call node, hiding the guard from the predicate-classification
            // pipeline. Append a synthetic If node (condition_vars includes <name>) so validation
            // predicates like `.chars().all(|c| c.is_ascii_*())` narrow taint on the guarded branch.
            if lang == "rust"
                && let Some((guard, let_name)) = detect_rust_let_match_guard(ast, code)
            {
                let if_node = emit_rust_match_guard_if(g, guard, &let_name, code, enclosing_func);
                connect_all(g, &[node], if_node, EdgeKind::Seq);
                let true_gate = g.add_node(NodeInfo {
                    kind: StmtKind::Seq,
                    ast: AstMeta {
                        span: (ast.end_byte(), ast.end_byte()),
                        enclosing_func: enclosing_func.map(|s| s.to_string()),
                    },
                    ..Default::default()
                });
                let false_gate = g.add_node(NodeInfo {
                    kind: StmtKind::Seq,
                    ast: AstMeta {
                        span: (ast.end_byte(), ast.end_byte()),
                        enclosing_func: enclosing_func.map(|s| s.to_string()),
                    },
                    ..Default::default()
                });
                connect_all(g, &[if_node], true_gate, EdgeKind::True);
                connect_all(g, &[if_node], false_gate, EdgeKind::False);
                return vec![true_gate, false_gate];
            }

            post_jsx_frontier
        }

        // Direct call nodes (Ruby `call`, Python `call`, etc. when they appear
        // as direct children of a block rather than wrapped in expression_statement)
        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
            let ord = *call_ordinal;
            *call_ordinal += 1;
            let (effective_preds, src_bindings, src_uses_only) = pre_emit_arg_source_nodes(
                g,
                ast,
                lang,
                code,
                enclosing_func,
                analysis_rules,
                preds,
            );
            let n = push_node(
                g,
                StmtKind::Call,
                ast,
                lang,
                code,
                enclosing_func,
                ord,
                analysis_rules,
            );
            apply_arg_source_bindings(g, n, &src_bindings, &src_uses_only);
            connect_all(g, &effective_preds, n, EdgeKind::Seq);

            // If the callee is a configured terminator, treat as a dead end
            if let Some(callee) = &g[n].call.callee
                && is_configured_terminator(callee, analysis_rules)
            {
                return Vec::new();
            }

            // Recurse into any function expressions nested in arguments.
            // Each nested function hits Kind::Function and becomes a separate body.
            // See sibling comment in CallWrapper arm: disconnect the
            // declaration-marker placeholder Seq edge after build_sub
            // returns, so the outer body's CFG isn't artificially branched.
            let nested = collect_nested_function_nodes(ast, lang);
            for func_node in nested {
                let placeholders = build_sub(
                    func_node,
                    &[n],
                    g,
                    lang,
                    code,
                    summaries,
                    file_path,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                    break_targets,
                    continue_targets,
                    throw_targets,
                    bodies,
                    next_body_id,
                    current_body_id,
                );
                for ph in placeholders {
                    let to_remove: Vec<_> = g.edges_connecting(n, ph).map(|e| e.id()).collect();
                    for eid in to_remove {
                        g.remove_edge(eid);
                    }
                }
            }

            vec![n]
        }

        // Assignment that may contain a call (Python `x = os.getenv(...)`, Ruby `x = gets()`)
        Kind::Assignment => {
            // JS/TS ternary-RHS split, same rationale as the CallWrapper branch.
            if matches!(lang, "javascript" | "typescript" | "tsx")
                && let (Some(left), Some(right)) = (
                    ast.child_by_field_name("left"),
                    ast.child_by_field_name("right"),
                )
            {
                let rhs = unwrap_parens(right);
                if rhs.kind() == "ternary_expression" {
                    let (lhs_text, lhs_labels) =
                        classify_ternary_lhs(left, lang, code, analysis_rules);
                    return build_ternary_diamond(
                        lhs_text,
                        lhs_labels,
                        rhs,
                        preds,
                        EdgeKind::Seq,
                        g,
                        lang,
                        code,
                        enclosing_func,
                        call_ordinal,
                        analysis_rules,
                    );
                }
            }

            //subscript-write lowering.  See
            // `try_lower_subscript_write` for the per-language shape
            // matrix and bail conditions.
            if crate::pointer::is_enabled()
                && let Some(n) = try_lower_subscript_write(
                    ast,
                    preds,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                )
            {
                return vec![n];
            }

            let has_call = has_call_descendant(ast, lang);
            let kind = if has_call {
                StmtKind::Call
            } else {
                StmtKind::Seq
            };
            let ord = if kind == StmtKind::Call {
                let o = *call_ordinal;
                *call_ordinal += 1;
                o
            } else {
                0
            };
            let n = push_node(
                g,
                kind,
                ast,
                lang,
                code,
                enclosing_func,
                ord,
                analysis_rules,
            );
            connect_all(g, preds, n, EdgeKind::Seq);
            // React JSX `dangerouslySetInnerHTML={{__html: x}}` synthesis
            // (Phase 06): chained after the assignment for shapes like
            // `const el = <div .../>`. No-op when no matching JSX descendant
            // is found in the assignment subtree.
            try_lower_jsx_dangerous_html(
                ast,
                &[n],
                g,
                lang,
                code,
                enclosing_func,
                call_ordinal,
                analysis_rules,
            )
        }

        // Trivia we drop completely ---------------------------------------------
        Kind::Trivia => preds.to_vec(),

        // React JSX attribute (`name={value}`).  The CFG builder synthesises
        // a sink Call node when the attribute is `dangerouslySetInnerHTML`
        // with a `{__html: x}` shape; otherwise no node is added (JSX
        // attributes carry no execution semantics on their own).
        Kind::JsxAttr => try_lower_jsx_dangerous_html(
            ast,
            preds,
            g,
            lang,
            code,
            enclosing_func,
            call_ordinal,
            analysis_rules,
        ),

        // ─────────────────────────────────────────────────────────────────
        //  Every other node = simple sequential statement
        // ─────────────────────────────────────────────────────────────────
        _ => {
            // React JSX `dangerouslySetInnerHTML={{__html: x}}` synthesis
            // (Phase 06): handles arrow-bodied components like
            // `() => <div .../>` that reach this arm without a wrapping
            // return / call statement.  Strictly additive — when no JSX
            // attribute matches the helper returns `preds` unchanged.
            let preds_v = try_lower_jsx_dangerous_html(
                ast,
                preds,
                g,
                lang,
                code,
                enclosing_func,
                call_ordinal,
                analysis_rules,
            );
            let n = push_node(
                g,
                StmtKind::Seq,
                ast,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, &preds_v, n, EdgeKind::Seq);
            vec![n]
        }
    }
}

/// Build an intraprocedural CFG and return (graph, entry_node).
///
/// * Walks the Tree‑Sitter AST.
/// * Creates `StmtKind::*` nodes only for *statement‑level* constructs to keep
///   the graph compact.
/// * Wires a synthetic `Entry` node in front and a synthetic `Exit` node after
///   all real sinks.
pub(crate) fn build_cfg<'a>(
    tree: &'a Tree,
    code: &'a [u8],
    lang: &str,
    file_path: &str,
    analysis_rules: Option<&LangAnalysisRules>,
) -> FileCfg {
    debug!(target: "cfg", "Building CFG for {:?}", tree.root_node());

    // Populate the per-file structural DFS-index map before any build_sub
    // call reads from it.  Cleared unconditionally at the end of this
    // function so thread-local state never leaks between files.
    populate_fn_dfs_indices(tree, lang);

    // harvest DTO class definitions before any param classifier
    // runs.  Empty for languages without a collector.  Cleared
    // alongside the DFS map at end-of-build_cfg.
    DTO_CLASSES.with(|cell| {
        *cell.borrow_mut() = dto::collect_dto_classes(tree.root_node(), lang, code);
    });
    // harvest same-file `type X = Map<...>` / `Set<...>` / `T[]`
    // aliases so JS/TS param classifiers resolve `m: ElementsMap`
    // to `LocalCollection`.  Empty for non-JS/TS languages.
    TYPE_ALIAS_LC.with(|cell| {
        *cell.borrow_mut() =
            dto::collect_type_alias_local_collections(tree.root_node(), lang, code);
    });
    // harvest per-function local-receiver type bindings, so a chained
    // inner call (`sess.createNativeQuery(sql).getResultList()`) can
    // rewrite the receiver `sess` to its type prefix
    // (`HibernateSession`) when the legacy literal-receiver classify
    // misses.  Java-only today; the helper is lang-agnostic, gated on
    // `constructor_type` recognising the RHS callee.
    populate_local_receiver_types(tree, lang, code);

    // Create the top-level body graph (BodyId(0)).
    let (mut g, entry, exit) = create_body_graph(0, code.len(), None);

    let mut summaries = FuncSummaries::new();
    let mut bodies: Vec<BodyCfg> = Vec::new();
    // BodyId(0) is reserved for top-level; function bodies start at 1.
    let mut next_body_id: u32 = 1;

    // Build the body below the synthetic ENTRY.
    let mut top_ordinal: u32 = 0;
    let mut top_breaks = Vec::new();
    let mut top_continues = Vec::new();
    let mut top_throws = Vec::new();
    let exits = build_sub(
        tree.root_node(),
        &[entry],
        &mut g,
        lang,
        code,
        &mut summaries,
        file_path,
        None,
        &mut top_ordinal,
        analysis_rules,
        &mut top_breaks,
        &mut top_continues,
        &mut top_throws,
        &mut bodies,
        &mut next_body_id,
        BodyId(0),
    );
    debug!(target: "cfg", "exits: {:?}", exits);
    // Wire every real exit to our synthetic EXIT node.
    for e in exits {
        connect_all(&mut g, &[e], exit, EdgeKind::Seq);
    }

    debug!(target: "cfg", "CFG DONE, top-level nodes: {}, bodies: {}", g.node_count(), bodies.len() + 1);

    if cfg!(debug_assertions) {
        for idx in g.node_indices() {
            debug!(target: "cfg", "  node {:>3}: {:?}", idx.index(), g[idx]);
        }
        for e in g.edge_references() {
            debug!(
                target: "cfg",
                "  edge {:>3} → {:<3} ({:?})",
                e.source().index(),
                e.target().index(),
                e.weight()
            );
        }
        let mut reachable: HashSet<NodeIndex> = Default::default();
        let mut bfs = Bfs::new(&g, entry);
        while let Some(nx) = bfs.next(&g) {
            reachable.insert(nx);
        }
        debug!(
            target: "cfg",
            "reachable nodes: {}/{}",
            reachable.len(),
            g.node_count()
        );
        if reachable.len() != g.node_count() {
            let unreachable: Vec<_> = g
                .node_indices()
                .filter(|i| !reachable.contains(i))
                .collect();
            debug!(target: "cfg", "‼︎ unreachable nodes: {:?}", unreachable);
        }
        let doms: Dominators<_> = simple_fast(&g, entry);
        debug!(target: "cfg", "dominator tree computed (len = {:?})", doms);
    }

    // Insert top-level body at position 0.
    let toplevel = BodyCfg {
        meta: BodyMeta {
            id: BodyId(0),
            kind: BodyKind::TopLevel,
            name: None,
            params: Vec::new(),
            param_types: Vec::new(),
            param_destructured_fields: Vec::new(),
            param_count: 0,
            span: (0, code.len()),
            parent_body_id: None,
            func_key: None,
            auth_decorators: Vec::new(),
            param_route_capture: Vec::new(),
        },
        graph: g,
        entry,
        exit,
    };
    bodies.insert(0, toplevel);
    // Sort by BodyId so that bodies[i].meta.id == BodyId(i).
    // Nested functions are pushed before their parents during build_sub,
    // so the Vec may be out of order before this sort.
    bodies.sort_by_key(|b| b.meta.id);

    // Extract import alias bindings for JS/TS files.
    let import_bindings = if matches!(
        lang,
        "javascript" | "typescript" | "tsx" | "python" | "php" | "rust"
    ) {
        extract_import_bindings(tree, code)
    } else {
        HashMap::new()
    };

    // Extract promisify-alias bindings (JS/TS only).  Applies a post-pass
    // over every call node whose callee is a recorded alias so the wrapped
    // function's labels (source/sanitizer/sink) carry through to the alias.
    let promisify_aliases = if matches!(lang, "javascript" | "typescript" | "tsx") {
        extract_promisify_aliases(tree, code)
    } else {
        HashMap::new()
    };

    let extra = analysis_rules.map(|r| r.extra_labels.as_slice());
    if !promisify_aliases.is_empty() {
        apply_promisify_labels(&mut bodies, &promisify_aliases, lang, extra);
    }

    // Phase 05 — JS/TS gated FILE_IO sinks (`readFile`, `writeFile`, ...)
    // for `node:fs/promises` callees. Runs after CFG construction so the
    // per-file local-import view is available; classify_all_ctx looks up
    // each call's leading identifier in the view to decide whether the
    // ImportedFromModule gate fires.
    let local_imports = if matches!(lang, "javascript" | "typescript" | "tsx") {
        let local_imports = extract_local_import_view(tree, code);
        if !local_imports.is_empty() {
            apply_gated_label_rules(&mut bodies, lang, extra, &local_imports);
        }
        local_imports
    } else {
        HashMap::new()
    };

    // Clear the per-file DFS-index map so it does not leak to the next
    // file built on this thread.
    clear_fn_dfs_indices();
    // same hygiene for the DTO map.
    DTO_CLASSES.with(|cell| cell.borrow_mut().clear());
    TYPE_ALIAS_LC.with(|cell| cell.borrow_mut().clear());
    LOCAL_RECEIVER_TYPES.with(|cell| cell.borrow_mut().clear());

    // collect every
    // declared inheritance / impl / implements relationship in the
    // file.  Per-language extractor in `cfg::hierarchy`; empty for
    // Go and C.  Each `(sub, super)` pair gets duplicated onto every
    // FuncSummary produced for the file by
    // `crate::cfg::export_summaries` so the information persists
    // through SQLite round-trips and re-merges into
    // `crate::callgraph::TypeHierarchyIndex` at call-graph build time.
    let hierarchy_edges = hierarchy::collect_hierarchy_edges(tree.root_node(), lang, code);

    // Phase 10 — Next.js entry-point detection.  Empty for non-JS/TS
    // languages; for JS/TS, keys each detected entry function by its
    // tree-sitter byte span so the SSA pass can match against
    // [`BodyMeta::span`] when seeding params.
    let entry_kinds = crate::entry_points::detect_entries_in_file(
        tree,
        code,
        std::path::Path::new(file_path),
        lang,
    );

    // Java safe-lookup field map: `final ... = Map.of(literal, literal, ...)`
    // declarations whose `.get(...)` results are bounded to the literal
    // set.  Empty for other languages.
    let safe_lookup_fields = safe_fields::collect_safe_lookup_fields(tree.root_node(), lang, code);

    // Java class-level constant scalars: `static final TYPE NAME = LITERAL;`
    // declarations whose name surfaces at a sink as a compile-time-bounded
    // value.  Empty for other languages.
    let class_constant_scalars =
        safe_fields::collect_class_constant_scalars(tree.root_node(), lang, code);

    FileCfg {
        bodies,
        summaries,
        import_bindings,
        promisify_aliases,
        hierarchy_edges,
        resolved_imports: Vec::new(),
        local_imports,
        entry_kinds,
        safe_lookup_fields,
        class_constant_scalars,
    }
}

/// Walk every CFG node in every body; for Call nodes whose callee matches a
/// promisify alias, classify the wrapped callee and union the resulting labels
/// into `info.taint.labels` (dedup by variant+caps).  The displayed callee
/// text is left unchanged so diagnostics still surface the alias name.
fn apply_promisify_labels(
    bodies: &mut [BodyCfg],
    aliases: &PromisifyAliases,
    lang: &str,
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) {
    for body in bodies.iter_mut() {
        let indices: Vec<NodeIndex> = body.graph.node_indices().collect();
        for idx in indices {
            let Some(callee) = body.graph[idx].call.callee.clone() else {
                continue;
            };
            let Some(alias) = aliases.get(&callee) else {
                continue;
            };
            // Inherit both flat and gated labels from the wrapped callee.
            // Gated sinks (e.g. `child_process.exec`) carry the same
            // capability semantics as flat sinks, just with arg-position
            // filtering at the call site; the promisify alias should
            // surface the wrapped function's sink class regardless of
            // which arm originally classified it.
            let mut wrapped_labels: Vec<crate::labels::DataLabel> =
                classify_all(lang, &alias.wrapped, extra)
                    .into_iter()
                    .collect();
            for gm in
                classify_gated_sink(lang, &alias.wrapped, |_| None, |_| None, |_| false).iter()
            {
                if !wrapped_labels.contains(&gm.label) {
                    wrapped_labels.push(gm.label);
                }
            }
            if wrapped_labels.is_empty() {
                continue;
            }
            let info = &mut body.graph[idx];
            for lbl in wrapped_labels {
                if !info.taint.labels.contains(&lbl) {
                    info.taint.labels.push(lbl);
                }
            }
        }
    }
}

/// Phase 05 — apply [`crate::labels::GatedLabelRule`] entries against
/// every call node in the file. The local-import view supplies the
/// gate evaluation context so a bare-name `readFile(...)` only fires
/// when the file actually imports `readFile` from `fs/promises` /
/// `node:fs/promises` (or is renamed via `import * as fsp` /
/// `import { readFile as rf }`). Strictly additive: only inserts new
/// labels, never removes existing ones.
fn apply_gated_label_rules(
    bodies: &mut [BodyCfg],
    lang: &str,
    _extra: Option<&[crate::labels::RuntimeLabelRule]>,
    local_imports: &std::collections::HashMap<String, String>,
) {
    let ctx = crate::labels::ClassificationContext {
        local_imports: Some(local_imports),
    };
    for body in bodies.iter_mut() {
        let indices: Vec<NodeIndex> = body.graph.node_indices().collect();
        for idx in indices {
            let Some(callee) = body.graph[idx].call.callee.clone() else {
                continue;
            };
            let labels = crate::labels::classify_gated_only(lang, &callee, Some(&ctx));
            if labels.is_empty() {
                continue;
            }
            let info = &mut body.graph[idx];
            for lbl in labels {
                if !info.taint.labels.contains(&lbl) {
                    info.taint.labels.push(lbl);
                }
            }
        }
    }
}

/// Build a `CalleeSite` carrying the richer per-call-site metadata for a
/// CFG node.
///
/// * `arity`, positional argument count.  `None` when `extract_arg_uses`
///   bailed out on splats/keyword-args (length 0 does not distinguish
///   zero-arg calls from unknown; we treat 0 as a concrete zero).  The
///   receiver is a separate channel via `CallMeta.receiver` and is not
///   represented in `arg_uses`, so `arity == arg_uses.len()` for calls.
/// * `receiver`, forwarded verbatim from `CallMeta.receiver` (already
///   normalized to the root identifier).
/// * `qualifier`, the segment(s) before the leaf identifier of the callee.
///   For **Rust** specifically, this is the *full* `::`-joined prefix (e.g.
///   `"crate::auth::token"` for `crate::auth::token::validate`) so that
///   cross-file `use`-map resolution in `callgraph.rs` has everything it
///   needs to walk an import chain.  For every other language the qualifier
///   remains the single segment immediately before the leaf (back-compat
///   with the legacy heuristic).  For method calls the qualifier is
///   redundant with `receiver` and is left `None`.
fn build_callee_site(callee: &str, info: &NodeInfo, lang: &str) -> crate::summary::CalleeSite {
    use crate::summary::CalleeSite;

    let receiver = info.call.receiver.clone();

    let arity = if info.kind == StmtKind::Call || receiver.is_some() {
        Some(info.call.arg_uses.len())
    } else {
        None
    };

    let qualifier = if receiver.is_some() {
        None
    } else if let Some(pos) = callee.rfind("::") {
        let prefix = &callee[..pos];
        if lang == "rust" {
            // Rust: preserve the full module path prefix so use-map
            // resolution can follow `use ...` chains without re-parsing.
            Some(prefix.to_string()).filter(|s| !s.is_empty())
        } else {
            Some(prefix.rsplit("::").next().unwrap_or(prefix).to_string()).filter(|s| !s.is_empty())
        }
    } else if let Some(pos) = callee.rfind('.') {
        let prefix = &callee[..pos];
        Some(prefix.rsplit('.').next().unwrap_or(prefix).to_string()).filter(|s| !s.is_empty())
    } else {
        None
    };

    CalleeSite {
        name: callee.to_string(),
        arity,
        receiver,
        qualifier,
        ordinal: info.call.call_ordinal,
    }
}

/// Convert the graph‑local `FuncSummaries` into serialisable [`FuncSummary`]
/// values suitable for cross‑file persistence.
pub(crate) fn export_summaries(
    summaries: &FuncSummaries,
    file_path: &str,
    lang: &str,
) -> Vec<FuncSummary> {
    summaries
        .iter()
        .map(|(key, local)| FuncSummary {
            name: key.name.clone(),
            file_path: file_path.to_owned(),
            lang: lang.to_owned(),
            param_count: local.param_count,
            param_names: local.param_names.clone(),
            source_caps: local.source_caps.bits(),
            sanitizer_caps: local.sanitizer_caps.bits(),
            sink_caps: local.sink_caps.bits(),
            propagating_params: local.propagating_params.clone(),
            propagates_taint: false,
            tainted_sink_params: local.tainted_sink_params.clone(),
            // Primary sink-location attribution: the legacy
            // `export_summaries` runs without tree/bytes access, so
            // cannot resolve sink node spans to line/col/snippet.
            // `ParsedFile::export_summaries_with_root` is responsible
            // for populating this field when it has tree access.
            param_to_sink: Vec::new(),
            callees: local.callees.clone(),
            container: local.container.clone(),
            disambig: local.disambig,
            kind: local.kind,
            // Rust use-map metadata is attached later in
            // `ParsedFile::export_summaries_with_root`, which has access to
            // the file's tree and scan root. Leaving these `None` here keeps
            // `export_summaries` a pure graph→summary transform.
            module_path: None,
            rust_use_map: None,
            rust_wildcards: None,
            // Hierarchy edges live on `FileCfg`, not on the
            // graph-local `FuncSummaries`.  `ParsedFile::export_summaries_with_root`
            // attaches them after this transform returns.
            hierarchy_edges: Vec::new(),
            // Phase-10 entry-point classification is attached after
            // this transform returns by
            // `ParsedFile::export_summaries_with_root` (which has
            // access to `FileCfg::entry_kinds`).
            entry_kind: None,
        })
        .collect()
}

// pub(crate) fn dump_cfg(g: &Cfg) {
//     debug!(target: "taint", "CFG DUMP: nodes = {}, edges = {}", g.node_count(), g.edge_count());
//     for idx in g.node_indices() {
//         debug!(target: "taint", "  node {:>3}: {:?}", idx.index(), g[idx]);
//     }
//     for e in g.edge_references() {
//         debug!(
//             target: "taint",
//             "  edge {:>3} → {:<3} ({:?})",
//             e.source().index(),
//             e.target().index(),
//             e.weight()
//         );
//     }
// }

#[cfg(test)]
mod cfg_tests;
