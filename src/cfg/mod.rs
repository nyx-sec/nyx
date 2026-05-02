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
use decorators::extract_auth_decorators;
pub(crate) use helpers::{
    collect_idents, collect_idents_with_paths, find_constructor_type_child, first_call_ident,
    has_call_descendant, member_expr_text, root_receiver_text, text_of,
};
use imports::{extract_import_bindings, extract_promisify_aliases};
#[cfg(test)]
use literals::has_sql_placeholders;
use literals::{
    arg0_kind_and_interpolation, call_ident_of, def_use, detect_go_replace_call_sanitizer,
    detect_rust_replace_chain_sanitizer, extract_arg_callees, extract_arg_string_literals,
    extract_arg_uses, extract_const_keyword_arg, extract_const_macro_arg, extract_const_string_arg,
    extract_destination_field_pairs, extract_destination_kwarg_pairs, extract_kwargs,
    extract_literal_rhs, extract_object_arg_property, extract_shell_array_payload_idents,
    find_call_node, find_call_node_deep, find_chained_inner_call, has_keyword_arg,
    has_object_arg_property, has_only_literal_args, is_parameterized_query_call,
    java_chain_arg0_kind_for_method, js_chain_arg0_kind_for_method,
    js_chain_outer_method_for_inner, ruby_chain_arg0_for_method, walk_chain_inner_call_args,
};
use params::{
    compute_container_and_kind, extract_param_meta, inject_framework_param_sources,
    is_configured_terminator,
};

/// Test-only re-export of [`extract_param_meta`] so the external
/// `tests/typed_extractors_audit.rs` harness can drive the per-param
/// classifier directly without spinning up the full scan pipeline.
pub fn extract_param_meta_for_test<'a>(
    func_node: tree_sitter::Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Vec<(String, Option<crate::ssa::type_facts::TypeKind>)> {
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
    /// `None`, downstream behaviour is identical to the pre-Phase-1
    /// engine.
    pub param_types: Vec<Option<crate::ssa::type_facts::TypeKind>>,
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
    /// [`crate::cfg::hierarchy`] for the per-language extraction
    /// rules and [`crate::callgraph::TypeHierarchyIndex`] for the
    /// downstream consumer.  Empty for languages without an
    /// extractor (Go, C) and for files with no inheritance / impl
    /// declarations.
    pub hierarchy_edges: Vec<(String, String)>,
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
    // with a `!` or `not` operator child.
    let is_negation_wrapper = matches!(
        cond.kind(),
        "unary_expression" | "not_operator" | "prefix_unary_expression" | "unary_not"
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
        "variable_declaration" | "lexical_declaration" => {
            // Walk direct children for the first variable_declarator with a value.
            let mut w = ast.walk();
            ast.named_children(&mut w)
                .find(|c| c.kind() == "variable_declarator")
                .and_then(|d| {
                    d.child_by_field_name("value")
                        .or_else(|| d.child_by_field_name("right"))
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
    // Only JS/TS expose `template_string` nodes; cheap early exit elsewhere.
    if !matches!(lang, "javascript" | "typescript") {
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
    if matches!(ast.kind(), "call_expression" | "call" | "new_expression") {
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

    // Case 2: `"scheme://host/" + x`, LHS is a string literal.
    if cur.kind() == "binary_expression" {
        let mut w2 = cur.walk();
        let mut ops = cur.children(&mut w2).filter(|c| !c.is_named());
        if !ops.any(|c| c.kind() == "+") {
            return None;
        }
        let left = cur.named_child(0)?;
        if matches!(left.kind(), "string" | "string_fragment") {
            let raw = text_of(left, code)?;
            let trimmed = if (raw.starts_with('"') && raw.ends_with('"'))
                || (raw.starts_with('\'') && raw.ends_with('\''))
                || (raw.starts_with('`') && raw.ends_with('`'))
            {
                if raw.len() >= 2 {
                    raw[1..raw.len() - 1].to_string()
                } else {
                    raw
                }
            } else {
                raw
            };
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    None
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
        outer_callee = Some(text.clone());
        text = inner_text;
        inner_callee_span = Some(inner_span);
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
        if let Some(member_text) = first_member_text(ast, code) {
            if outer_callee.is_none() && text != member_text {
                outer_callee = Some(text.clone());
            }
            text = member_text;
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
            let gate_callee_text = if call_ast.is_some() {
                text.clone()
            } else {
                // Inner call reached via wrapper, use the call-expression's
                // function name directly. Falls back to `text` so non-call-
                // expression kinds (method calls, Ruby `call` nodes, macros)
                // still have a usable callee string.
                cn.child_by_field_name("function")
                    .or_else(|| cn.child_by_field_name("method"))
                    .or_else(|| cn.child_by_field_name("name"))
                    .and_then(|f| text_of(f, code))
                    .unwrap_or_else(|| text.clone())
            };
            let matches = classify_gated_sink(
                lang,
                &gate_callee_text,
                |idx| {
                    extract_const_string_arg(cn, idx, code).or_else(|| {
                        // C/C++ preprocessor macros and PHP `define`d constants
                        // surface as identifier nodes, not string literals.
                        // Falling back to the macro-arg extractor for those
                        // languages lets gates like `curl_easy_setopt` /
                        // `curl_setopt` activate on a `CURLOPT_POSTFIELDS`
                        // ident match instead of firing conservatively on
                        // every positional arg.
                        if matches!(lang, "c" | "cpp" | "c++" | "php") {
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

    let (defines, uses, extra_defines) = def_use(ast, lang, code);

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
    let mut arg_callees = if kind == StmtKind::Call {
        call_ast
            .map(|cn| extract_arg_callees(cn, lang, code))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

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
                // Pull the receiver from the object/attribute-owner field.
                let func_child = cn.child_by_field_name("function");
                let recv_node = match func_child {
                    Some(fc) if fc.kind() == "member_expression" || fc.kind() == "attribute" => {
                        fc.child_by_field_name("object")
                    }
                    Some(fc) if fc.kind() == "field_expression" => fc.child_by_field_name("value"),
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
        },
        taint: TaintMeta {
            labels,
            const_text,
            defines,
            uses,
            extra_defines,
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
    let n = g.add_node(NodeInfo {
        kind: StmtKind::Call,
        call: CallMeta {
            callee: Some("__index_set__".to_string()),
            receiver: Some(arr_text.clone()),
            arg_uses: vec![vec![idx_text.clone()], rhs_uses.clone()],
            call_ordinal: ord,
            ..Default::default()
        },
        taint: TaintMeta {
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
                        )
                })
                .unwrap_or(false);

            // Fresh break/continue targets scoped to this loop
            let mut loop_breaks = Vec::new();
            let mut loop_continues = Vec::new();

            // Body = first (and usually only) block child.
            let body = ast
                .child_by_field_name("body")
                .or_else(|| {
                    let mut c = ast.walk();
                    ast.children(&mut c)
                        .find(|n| lookup(lang, n.kind()) == Kind::Block)
                })
                .expect("loop without body");

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
                connect_all(g, &[call_idx], ret, EdgeKind::Seq);

                // Recurse into any function expressions nested inside the
                // returned call's arguments (e.g.
                // `return new Promise((res, rej) => { ... })`). Without this
                // the executor and any further inner callbacks are silently
                // swallowed and the gated sinks they contain become invisible
                // to classification. Mirrors the same recursion done by the
                // CallWrapper / CallFn arms. Motivated by CVE-2025-64430.
                let nested = collect_nested_function_nodes(ast, lang);
                for func_node in nested {
                    build_sub(
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
                }

                Vec::new()
            } else {
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
                connect_all(g, preds, ret, EdgeKind::Seq);
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
                // any inner gated sinks.
                let nested = collect_nested_function_nodes(ast, lang);
                for func_node in nested {
                    build_sub(
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
            let param_names: Vec<String> = param_meta.iter().map(|(n, _)| n.clone()).collect();
            let param_types: Vec<Option<crate::ssa::type_facts::TypeKind>> =
                param_meta.iter().map(|(_, t)| t.clone()).collect();

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
                    param_count,
                    span: (ast.start_byte(), ast.end_byte()),
                    parent_body_id: Some(current_body_id),
                    func_key: Some(body_func_key),
                    auth_decorators,
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

            // If the callee is a configured terminator, treat as a dead end
            if kind == StmtKind::Call
                && let Some(callee) = &g[node].call.callee
                && is_configured_terminator(callee, analysis_rules)
            {
                return Vec::new();
            }

            // Recurse into any function expressions nested in arguments
            // (e.g. `app.get('/path', function(req, res) { ... })`)
            // so that they get proper function summaries.
            let nested = collect_nested_function_nodes(ast, lang);
            for func_node in nested {
                build_sub(
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

            vec![node]
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
            let nested = collect_nested_function_nodes(ast, lang);
            for func_node in nested {
                build_sub(
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
            vec![n]
        }

        // Trivia we drop completely ---------------------------------------------
        Kind::Trivia => preds.to_vec(),

        // ─────────────────────────────────────────────────────────────────
        //  Every other node = simple sequential statement
        // ─────────────────────────────────────────────────────────────────
        _ => {
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
            connect_all(g, preds, n, EdgeKind::Seq);
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
            param_count: 0,
            span: (0, code.len()),
            parent_body_id: None,
            func_key: None,
            auth_decorators: Vec::new(),
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

    // Clear the per-file DFS-index map so it does not leak to the next
    // file built on this thread.
    clear_fn_dfs_indices();
    // same hygiene for the DTO map.
    DTO_CLASSES.with(|cell| cell.borrow_mut().clear());
    TYPE_ALIAS_LC.with(|cell| cell.borrow_mut().clear());

    // collect every
    // declared inheritance / impl / implements relationship in the
    // file.  Per-language extractor in `cfg::hierarchy`; empty for
    // Go and C.  Each `(sub, super)` pair gets duplicated onto every
    // FuncSummary produced for the file by
    // `crate::cfg::export_summaries` so the information persists
    // through SQLite round-trips and re-merges into
    // `crate::callgraph::TypeHierarchyIndex` at call-graph build time.
    let hierarchy_edges = hierarchy::collect_hierarchy_edges(tree.root_node(), lang, code);

    FileCfg {
        bodies,
        summaries,
        import_bindings,
        promisify_aliases,
        hierarchy_edges,
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
