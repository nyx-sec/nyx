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

#![allow(clippy::let_and_return, clippy::unnecessary_map_or)]

use fast_kind::{FastKind, lookup_node};
use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::prelude::*;
use tracing::{debug, warn};
use tree_sitter::{Node, Tree};

use crate::labels::{
    Cap, DataLabel, Kind, LangAnalysisRules, classify, classify_all, classify_gated_sink,
    classify_gated_sink_with_presence, lookup,
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
mod fast_kind;
mod helpers;
mod hierarchy;
mod imports;
mod keyword_args;
mod literals;
mod module_consts;
mod nested_calls;
mod params;
pub(crate) mod python_shapes;
mod rust_receivers;
pub mod safe_fields;
use blocks::{build_begin_rescue, build_switch, build_try, in_duplicate_finally_copy};
use helpers::{
    call_fn_callee_text, call_ident_at_or_under, call_node_ident_with_span,
    collect_nested_function_nodes, collect_rhs_object_literal, derive_anon_fn_name_from_context,
    find_classifiable_inner_call, find_inner_sink_call, find_inner_source_or_sink_call,
    first_call_ident_with_span, first_callback_sink_call, first_member_label, first_member_text,
    is_raii_factory, is_subscript_kind, nested_member_sink_calls, php_direct_operand_sources,
    php_output_construct, php_output_value_uses, root_member_receiver,
    scope_sets_html_content_type, subscript_components, subscript_lhs_node,
};
pub use nested_calls::{CallSlot, NestedCall, NestedCallTree, NestedUse};
// Re-exports so sibling submodules can keep using `super::name` for
// helpers that physically live in `helpers.rs`.
use conditions::{
    build_condition_chain, build_ternary_diamond, classify_ternary_lhs,
    detect_rust_let_match_guard, emit_rust_match_guard_if, extract_null_check,
    find_ternary_rhs_wrapper, is_boolean_operator, ternary_parts, unwrap_parens,
};
use decorators::{extract_auth_decorators, extract_route_path_captures};
pub(crate) use helpers::{
    HeaderExpr, RmwAssign, ValidSourceGuard, collect_idents, collect_idents_with_paths,
    control_header_expr, find_condition_subtree, find_constructor_type_child, first_call_ident,
    has_call_descendant, has_function_descendant, member_expr_text, member_expr_text_full,
    node_str, rmw_assignment, rmw_statement, rmw_target_define, rmw_target_reads,
    root_receiver_text, slice_str, subtree_has_call, text_of,
};
use imports::{
    collect_python_noreturn_imports, extract_import_bindings, extract_local_import_view,
    extract_promisify_aliases, extract_python_import_paths, rust_bare_join_crate_prefix,
};
use literals::go_leading_arg_is_context;
#[cfg(test)]
use literals::has_sql_placeholders;
use literals::literal_scalar_collection_rhs;
use literals::{
    ParamQueryShape, call_has_arg_at, call_ident_of, def_use, destination_field_reading_source,
    detect_go_replace_call_sanitizer, detect_rust_replace_chain_sanitizer,
    extract_arg_bare_name_mask, extract_arg_callees, extract_arg_raw_string_mask,
    extract_arg_string_literals, extract_arg_string_prefixes, extract_arg_uses,
    extract_const_keyword_arg, extract_const_macro_arg, extract_const_string_arg,
    extract_destination_field_pairs, extract_destination_kwarg_pairs, extract_kwargs,
    extract_literal_rhs, extract_object_arg_property, extract_shell_array_payload_idents,
    find_call_node, find_call_node_deep, find_chained_gated_sink_call, find_chained_inner_call,
    find_orm_query_chain_call, has_keyword_arg, has_object_arg_property, has_only_literal_args,
    is_object_create_null_call, is_rust_format_style_macro, java_chain_arg0_kind_for_method,
    js_arg_is_prototype_object, js_arg_is_string_valued, js_arg_is_structured_condition,
    js_chain_arg0_kind_for_method, js_chain_outer_method_for_inner, js_orm_query_arg0_is_uid_ref,
    js_positional_arity, js_shell_option_argv_positions, js_sql_template_raw_splices,
    parameterized_query_shape, python_positional_arity, ruby_statement_ar_queries_safe,
    walk_chain_inner_call_args,
};
use params::{
    compute_container_and_kind, extract_param_meta, inject_framework_param_sources,
    is_terminator_call,
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
    /// Per-file set of local names bound to a never-returning Python
    /// framework helper (`from flask import abort`, `... import abort as
    /// deny`).  Populated at the top of [`build_cfg`] for Python and read
    /// by `params::is_terminator_call`.
    pub(crate) static PYTHON_NORETURN_IMPORTS: RefCell<std::collections::HashSet<String>>
        = RefCell::new(std::collections::HashSet::new());
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
    // The walk only records children of kind `variable_declarator`; a
    // grammar without that node kind (Go, Rust, C, Python, ...) can never
    // produce a binding, so skip the whole-tree walk.
    if tree
        .language()
        .id_for_node_kind("variable_declarator", true)
        == 0
    {
        LOCAL_RECEIVER_TYPES.with(|cell| cell.borrow_mut().clear());
        return;
    }
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
    if lookup_node(lang, root) == Kind::Function {
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
    if !is_root && lookup_node(lang, node) == Kind::Function {
        return;
    }
    if node.fkind() == "local_variable_declaration"
        || node.fkind() == "variable_declarator"
        || node.fkind() == "let_declaration"
        || node.fkind() == "short_var_declaration"
        || node.fkind() == "var_spec"
    {
        let mut cursor = node.walk();
        for declarator in node.children(&mut cursor) {
            if declarator.fkind() != "variable_declarator" {
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
    match lookup_node(lang, node) {
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
        if lookup_node(lang, cur) == Kind::Function {
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
/// available.  Java falls back to the receiver's declared type
/// (`java_declared_receiver_kind`), so a chain hop on an injected field
/// (`em.createQuery(q).getResultList()`, `http.send(req).body()`) is typed
/// too.  Returns `None` when neither source types the receiver or the
/// `TypeKind` has no label prefix.
pub(crate) fn local_receiver_type_prefix(
    inner_call: Node<'_>,
    receiver: &str,
    lang: &str,
    code: &[u8],
) -> Option<&'static str> {
    let local = enclosing_fn_start(inner_call, lang)
        .and_then(|fn_start| lookup_local_receiver_type(fn_start, receiver));
    let kind = match local {
        Some(kind) => kind,
        None if lang == "java" => java_call_receiver_decl_type(inner_call, code)?,
        None => return None,
    };
    kind.label_prefix()
}

/// Populate the per-file DFS-index map from a preorder walk of the
/// tree-sitter AST.  Every node classifying as `Kind::Function` gets
/// a monotonically increasing `u32` starting at 0.
fn populate_fn_dfs_indices(tree: &Tree, lang: &str) {
    let is_fn = function_kind_table(tree, lang);
    let mut map = HashMap::new();
    let mut counter: u32 = 0;
    // Preorder walk on one cursor; the order and the counter are the same as
    // a recursive descent over `children()`.
    let mut cursor = tree.walk();
    'walk: loop {
        let n = cursor.node();
        if is_fn.get(n.kind_id() as usize).copied().unwrap_or(false) {
            map.insert(n.start_byte(), counter);
            counter += 1;
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                break 'walk;
            }
        }
    }
    FN_DFS_INDICES.with(|cell| *cell.borrow_mut() = map);
}

/// One cached [`function_kind_table`]: grammar, language slug, table.
type FunctionKindEntry = (tree_sitter::Language, String, std::rc::Rc<Vec<bool>>);

thread_local! {
    /// Per-thread cache of [`function_kind_table`] results, one entry per
    /// (grammar, language slug) pair seen on this thread.
    static FUNCTION_KIND_TABLES: RefCell<Vec<FunctionKindEntry>>
        = const { RefCell::new(Vec::new()) };
}

/// For every node-kind id of the tree's grammar, whether `lookup(lang, kind)`
/// is [`Kind::Function`].  Lets a walk test `node.kind_id()` instead of
/// resolving the kind name and hashing it on every node.
fn function_kind_table(tree: &Tree, lang: &str) -> std::rc::Rc<Vec<bool>> {
    let language = tree.language();
    FUNCTION_KIND_TABLES.with(|cell| {
        let mut cache = cell.borrow_mut();
        if let Some((_, _, table)) = cache
            .iter()
            .find(|(l, name, _)| *l == *language && name == lang)
        {
            return table.clone();
        }
        let count = language.node_kind_count();
        let table: Vec<bool> = (0..count)
            .map(|id| {
                language
                    .node_kind_for_id(id as u16)
                    .is_some_and(|name| lookup(lang, name) == Kind::Function)
            })
            .collect();
        let table = std::rc::Rc::new(table);
        cache.push(((*language).clone(), lang.to_string(), table.clone()));
        table
    })
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

/// A branch condition that tests one variable against its "nothing was
/// produced" value: `if (f)`, `if (!f)`, `f == NULL`, `NULL != f`,
/// `f is None`, `$fh === false`, `fd < 0`, `err != nil`.
///
/// Recognised from the AST at CFG build (see
/// `conditions::extract_null_check`), so the resource passes never re-parse
/// condition text.  `null_on_true` names the branch on which `var` holds the
/// null / failure value: `true` when the condition holding means "null"
/// (`f == NULL`, `!f`, `fd < 0`), `false` when the condition failing does
/// (`if (f)`, `f != NULL`).  CFG `True` / `False` edges carry the value of
/// the whole condition, so [`NullCheck::null_edge`] maps straight onto them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NullCheck {
    pub var: String,
    pub null_on_true: bool,
}

impl NullCheck {
    /// The edge on which `var` is null (or the failure sentinel).
    pub fn null_edge(&self) -> EdgeKind {
        if self.null_on_true {
            EdgeKind::True
        } else {
            EdgeKind::False
        }
    }

    /// The edge on which `var` is non-null.  For a Go error companion
    /// (`err != nil`) this is the branch where the call failed.
    pub fn non_null_edge(&self) -> EdgeKind {
        if self.null_on_true {
            EdgeKind::False
        } else {
            EdgeKind::True
        }
    }
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

impl BinOp {
    /// True for the six comparison operators (result is a boolean 0/1).
    pub fn is_comparison(self) -> bool {
        matches!(
            self,
            BinOp::Eq | BinOp::NotEq | BinOp::Lt | BinOp::LtEq | BinOp::Gt | BinOp::GtEq
        )
    }
}

/// A branch condition captured as a pure integer-arithmetic + comparison
/// expression tree at CFG-build time (where the real tree-sitter AST is
/// available, so operator precedence and parentheses are correct by
/// construction — no text re-parsing downstream).
///
/// Built only when *every* leaf is an integer literal or a plain identifier
/// and *every* interior node is an arithmetic / comparison / bitwise operator,
/// a unary `-`, or a parenthesis.  Any call, field access, string, container,
/// or compound-boolean (`&&` / `||`) subtree makes the builder return `None`
/// for the whole condition.  Identifiers are stored by name and resolved to
/// their constant SSA value at fold time
/// ([`crate::ssa::const_prop::fold_constant_branches`]); the actual numeric
/// evaluation is shared in [`CondArith::eval`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CondArith {
    /// Integer literal.
    Lit(i64),
    /// Identifier — resolved to a constant integer at fold time, else unknown.
    Var(String),
    /// Unary integer negation: `-x`.
    Neg(Box<CondArith>),
    /// Binary arithmetic / bitwise / comparison.
    Bin(BinOp, Box<CondArith>, Box<CondArith>),
}

/// Result of folding a [`CondArith`] against a constant environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondVal {
    Int(i64),
    Bool(bool),
}

impl CondArith {
    /// Evaluate against a variable→constant-integer resolver.  Returns `None`
    /// the moment anything is non-constant or an operation is undefined
    /// (division/modulo by zero, arithmetic overflow, type mismatch), so a
    /// caller can only ever prune on a *definite* result.  All integer
    /// arithmetic is checked; overflow yields `None` rather than a wrapped
    /// value, which keeps the fold sound across the i32/i64 gap.
    pub fn eval(&self, resolve: &impl Fn(&str) -> Option<i64>) -> Option<CondVal> {
        match self {
            CondArith::Lit(n) => Some(CondVal::Int(*n)),
            CondArith::Var(name) => resolve(name).map(CondVal::Int),
            CondArith::Neg(inner) => match inner.eval(resolve)? {
                CondVal::Int(n) => n.checked_neg().map(CondVal::Int),
                CondVal::Bool(_) => None,
            },
            CondArith::Bin(op, l, r) => {
                let lhs = match l.eval(resolve)? {
                    CondVal::Int(n) => n,
                    CondVal::Bool(_) => return None,
                };
                let rhs = match r.eval(resolve)? {
                    CondVal::Int(n) => n,
                    CondVal::Bool(_) => return None,
                };
                let arith = |v: Option<i64>| v.map(CondVal::Int);
                match op {
                    BinOp::Add => arith(lhs.checked_add(rhs)),
                    BinOp::Sub => arith(lhs.checked_sub(rhs)),
                    BinOp::Mul => arith(lhs.checked_mul(rhs)),
                    // Java/Rust integer division and modulo both truncate
                    // toward zero; `checked_*` rejects div-by-zero and
                    // i64::MIN / -1 overflow.
                    BinOp::Div => arith(lhs.checked_div(rhs)),
                    BinOp::Mod => arith(lhs.checked_rem(rhs)),
                    BinOp::BitAnd => arith(Some(lhs & rhs)),
                    BinOp::BitOr => arith(Some(lhs | rhs)),
                    BinOp::BitXor => arith(Some(lhs ^ rhs)),
                    BinOp::LeftShift => u32::try_from(rhs)
                        .ok()
                        .and_then(|s| lhs.checked_shl(s))
                        .map(CondVal::Int),
                    BinOp::RightShift => u32::try_from(rhs)
                        .ok()
                        .and_then(|s| lhs.checked_shr(s))
                        .map(CondVal::Int),
                    BinOp::Eq => Some(CondVal::Bool(lhs == rhs)),
                    BinOp::NotEq => Some(CondVal::Bool(lhs != rhs)),
                    BinOp::Lt => Some(CondVal::Bool(lhs < rhs)),
                    BinOp::LtEq => Some(CondVal::Bool(lhs <= rhs)),
                    BinOp::Gt => Some(CondVal::Bool(lhs > rhs)),
                    BinOp::GtEq => Some(CondVal::Bool(lhs >= rhs)),
                }
            }
        }
    }

    /// Evaluate to a definite boolean, or `None`.  The top-level node must be a
    /// comparison (a bare integer is not a branch condition we fold).
    pub fn eval_bool(&self, resolve: &impl Fn(&str) -> Option<i64>) -> Option<bool> {
        match self.eval(resolve)? {
            CondVal::Bool(b) => Some(b),
            CondVal::Int(_) => None,
        }
    }

    /// Collect every identifier name referenced by the tree.
    pub fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            CondArith::Lit(_) => {}
            CondArith::Var(name) => {
                if !out.iter().any(|v| v == name) {
                    out.push(name.clone());
                }
            }
            CondArith::Neg(inner) => inner.collect_vars(out),
            CondArith::Bin(_, l, r) => {
                l.collect_vars(out);
                r.collect_vars(out);
            }
        }
    }
}

/// Call-related metadata for CFG nodes.
/// Relation between a node's recorded `callee` and the call the node is.
///
/// `callee` can be promoted from a call nested in the node, so the resource
/// passes need to know whether it still describes the call whose result the
/// node's definition holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CalleeNesting {
    /// The callee is the node's own call, or a chain head used as a receiver
    /// (`createReadStream(p).on(..)`), whose result is the acquired value.
    #[default]
    Own,
    /// Promoted from the arguments of another call (`wrap(open(p))`): the
    /// definition holds the outer call's result, not the nested value.
    InArg,
    /// As `InArg`, but through an object / array / map literal in the
    /// arguments (`rq({ files: createReadStream(p) })`): the value is stored
    /// into an aggregate that the outer call receives.
    InAggregateArg,
    /// A member read hoisted out of a callback argument over the node's own
    /// callee (`describe(.., () => { fs.createReadStream(p) })`).  Names no
    /// call of this node.
    Hoisted,
}

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
    /// Identifiers syntactically contained in a nested inner sink call when the
    /// node's `Sink` label was contributed by
    /// `find_classifiable_inner_call` /
    /// `find_inner_sink_call` overriding the outer callee.
    ///
    /// A flattened aggregate node (`Ok(Reader { meta: <tainted>, h:
    /// File::open(const) })`) collapses the whole expression into one CFG
    /// node whose `Sink` label applies only to the inner `File::open`
    /// sub-expression, yet whose def-use set (and hence the SSA Call's
    /// implicit args) includes the tainted sibling field `meta`.  Without a
    /// filter the sink scan's aggregate fallback would treat that sibling as
    /// reaching the sink.  When `Some`, the SSA sink scan drops any tainted
    /// value whose `var_name` is present but NOT in this set; unnamed
    /// temporaries are kept (conservative for recall).  `None` for the common
    /// case where the classified call IS the outer AST node.
    #[serde(default)]
    pub sink_reaching_uses: Option<Vec<String>>,
    /// Keyword/named arguments attached to this call, in source order.
    ///
    /// Each entry is `(keyword_name, uses)` where `uses` are the identifier
    /// references from the keyword's value expression (same shape as an entry
    /// in `arg_uses`).  Populated for languages that expose named arguments
    /// at the call site (e.g. Python `func(shell=True)`, Ruby hash-arg style).
    /// Empty for languages without named arguments and for calls that use
    /// only positional arguments.
    pub kwargs: Vec<(String, Vec<String>)>,
    /// Ruby keyword arguments as `(name, position in arg_uses)`.  Ruby passes
    /// them as `pair` entries in the argument list, so each sits in a
    /// positional slot; `keyword_args::reorder_keyword_args` moves the ones
    /// aimed at a same-file method to that method's parameter slot.  Empty for
    /// other languages and for calls without keywords.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kw_arg_positions: Vec<(String, usize)>,
    /// String-literal value at each positional argument of this call, parallel
    /// to `arg_uses`, `Some(s)` when the argument is a syntactic string
    /// literal, `None` otherwise.  Empty for non-call nodes or when positional
    /// boundaries can't be determined.  Consumed by the static-map abstract
    /// analysis (and future literal-aware passes) so they don't need the
    /// source bytes.
    pub arg_string_literals: Vec<Option<String>>,
    /// Constant leading text of each positional argument that is a string
    /// built from a literal head (`"https://h/" + id`, a template literal, an
    /// f-string, `fmt.Sprintf("https://h/%s", id)`), parallel to
    /// `arg_string_literals`.  `None` for plain literals (see above) and for
    /// arguments with no literal head.  Empty when no argument has one.
    /// Lets sinks and URL builders that take the URL at a position other
    /// than the first read the prefix of the argument they care about.
    #[serde(default)]
    pub arg_string_prefixes: Vec<Option<String>>,
    /// Bit `i` is set when positional argument `i` is exactly a name: an
    /// identifier, or a member path of identifiers (`clean`, `cfg.root`),
    /// with parentheses and PHP's `argument` wrapper peeled.  The SSA use of
    /// such an argument is its whole value, so a fact on that use describes
    /// the argument.  An expression over one name (`x + "/.."`, `x[1:]`) has
    /// the same single SSA use but leaves its bit clear.  Positions past 63
    /// are never set.
    #[serde(default)]
    pub arg_bare_names: u64,
    /// Positional arguments that are Go raw string literals (bit `i` for
    /// argument `i`).  `arg_string_literals[i]` is then the literal's value,
    /// where for an interpreted literal it is the source text between the
    /// quotes, escapes unread.  Go only; positions past 63 are never set.
    #[serde(default)]
    pub arg_raw_string_mask: u64,
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
    /// Where `callee` sits relative to the node's own call.  See
    /// [`CalleeNesting`].
    #[serde(default)]
    pub callee_nesting: CalleeNesting,
    /// Bare variables whose ownership this constructor takes over: the
    /// arguments of a Java wrapper constructor (`new BufferedInputStream(in)`,
    /// nested wrappers included) and the initialiser of a C++ smart-pointer
    /// declaration (`std::unique_ptr<T> p(raw)`).  Whether the handoff
    /// happens is decided by the resource passes; see
    /// `state::transfer::DefaultTransfer::apply_call`.
    #[serde(default)]
    pub ctor_owned_args: Vec<String>,
    /// True when this call is `Object.create(null)` (or alias). The returned
    /// value has no prototype chain.  Consumed by TypeFacts to tag the
    /// SsaValue with [`crate::ssa::type_facts::TypeKind::NullPrototypeObject`]
    /// so PROTOTYPE_POLLUTION suppression can fire flow-sensitively at the
    /// synthetic `__index_set__` sink.  Set during CFG node construction so
    /// SSA does not need to re-walk the AST.
    #[serde(default)]
    pub produces_null_proto: bool,
    /// Provenance for a `Sink` label that was HOISTED onto this wrapper call
    /// from an inner call nested inside a callback-argument function literal.
    ///
    /// `first_member_label` descends through function literals, so a wrapper
    /// like `queryInterface.sequelize.transaction(async (t) => {
    /// queryInterface.sequelize.query(`…const DDL…`, { transaction: t }) })`
    /// inherits the inner `sequelize.query` `Sink` label — but the wrapper's
    /// own arguments are the callback, not the SQL payload.  This records the
    /// INNER sink call's own payload-arg positions + per-argument string
    /// literals so the `cfg-unguarded-sink` syntactic payload-const check
    /// (`sink_payload_args_syntactic_const`) can prove the *inner* payload is
    /// a constant (suppress the phantom wrapper finding) while a tainted inner
    /// payload still fires.  `None` for the common case (no hoist, or the
    /// hoisted label did not come from inside a callback body).
    #[serde(default)]
    pub hoisted_sink: Option<Box<HoistedSink>>,
    /// How the calls inside this node's expression nest and which operands
    /// each one wraps (see [`NestedCallTree`]).  `None` when the node holds a
    /// single call with every operand inside it, the shape the flat
    /// `arg_uses` / `taint.uses` view already describes exactly.
    #[serde(default)]
    pub nested_calls: Option<Box<NestedCallTree>>,
    /// Java: service kind of the call's receiver taken from its declared
    /// type (a field, formal or local such as `private JdbcTemplate jdbc;`).
    /// Spring injects these receivers, so no constructor in the method body
    /// types them for SSA type facts.  Type-qualified label resolution uses
    /// it after the SSA type facts and path environment.  Only set when the
    /// call carries no `Sink` label of its own; see
    /// `java_declared_receiver_kind` for the kinds that qualify.
    #[serde(default)]
    pub receiver_decl_type: Option<crate::ssa::type_facts::TypeKind>,
}

/// Recorded provenance of a callback-nested inner sink call whose `Sink` label
/// was hoisted onto an outer wrapper node by `first_member_label`.  See
/// [`CallMeta::hoisted_sink`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HoistedSink {
    /// The inner sink call's payload-arg positions (its gate's `payload_args`,
    /// with the dynamic `ALL_ARGS_PAYLOAD` sentinel already expanded to the
    /// inner call's arity).  `None` when the inner sink carries no gate (an
    /// unrestricted sink — every argument is a payload position).
    pub payload_args: Option<Vec<usize>>,
    /// The inner sink call's per-positional-argument string literals, parallel
    /// to the inner call's positional arguments (same shape as
    /// [`CallMeta::arg_string_literals`]).
    pub arg_string_literals: Vec<Option<String>>,
}

impl HoistedSink {
    /// Whether every payload position of the inner sink call holds a captured
    /// constant string literal.  `payload_args = Some(non-empty)` lists the
    /// positions to check; `None` or empty means every argument is a payload,
    /// so every recorded argument must be a literal and there must be at least
    /// one (an empty list is unproven).
    pub fn is_constant(&self) -> bool {
        crate::cfg_analysis::guards::payload_positions_all_literal(
            &self.payload_args,
            &self.arg_string_literals,
        )
    }
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
    /// The node binds `defines` to an array / list / tuple literal whose
    /// elements are all string or number literals, with no uses
    /// (`const NAMES = ["a", "b"]`).  A loop over such a collection only ever
    /// binds those literals.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub const_collection: bool,
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
    /// Property shape of a JS/TS object-literal RHS when this node binds the
    /// single variable in `defines` to one (`const cfg = { bin: "ls", arg:
    /// req.query.a }`).  `None` for every other RHS.
    ///
    /// Lowering gives the whole literal one SSA value, so a read of a
    /// property the body never writes (`cfg.bin`) only exists as an unbacked
    /// phantom value with no taint of its own.  Field-aware sink suppression
    /// uses this shape to tell a property that is provably clean (a literal,
    /// or absent from a closed literal) from a read of an object that is
    /// tainted as a whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rhs_object_literal: Option<Box<RhsObjectLiteral>>,
}

/// Property shape of a JS/TS object literal.  See
/// [`TaintMeta::rhs_object_literal`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RhsObjectLiteral {
    /// Properties in source order.  A key written twice keeps both entries;
    /// readers take the last one, as JS does.
    pub fields: SmallVec<[(String, RhsObjectSlot); 4]>,
    /// True when the literal can hold keys that `fields` does not list or
    /// can overwrite listed ones: a spread (`...rest`), a computed key
    /// (`[k]: v`), or a method / accessor.
    pub open: bool,
}

/// Value of one property in an [`RhsObjectLiteral`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RhsObjectSlot {
    /// Syntactic literal: string or template without substitutions, number,
    /// boolean, `null`, `undefined`, regex.
    Literal,
    /// Bare identifier value, including shorthand properties (`{ name }`).
    Ident(String),
    /// Nested object literal.
    Object(Box<RhsObjectLiteral>),
    /// Any other expression (call, member access, binary, interpolated
    /// template, ...).
    Complex,
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

/// What a C / C++ assignment's value is, for the resource passes: whether it
/// copies a whole handle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RhsShape {
    /// An identifier, or any shape not listed below: the new
    /// name may hold the handle.
    #[default]
    Whole,
    /// The address of a sub-object (`c = &ac->c`) or arithmetic
    /// (`q = p + 1`): a different value that a tracked handle read by it
    /// does not move into.
    SubObject,
    /// An aggregate initializer (`cc = {.names = names}`, `(S){f}`): a handle
    /// listed in it is now owned by the aggregate, which is not itself a
    /// handle.
    Aggregate,
    /// A field, element or dereference read (`cur = cur->next`): the value
    /// is another object reached from the handle.
    Projection,
    /// A cast of a plain name (`lp = (T **)src`): a second view of the same
    /// object.  The original name keeps the handle, and releasing either
    /// name releases it.
    CastView,
}

/// The call a condition header evaluates; see [`NodeInfo::cond_call`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CondCall {
    /// Callee text, spelled like `CallMeta::callee`.
    pub callee: String,
    /// Identifiers of each positional argument, like `CallMeta::arg_uses`.
    pub arg_uses: Vec<Vec<String>>,
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
    /// For If nodes whose condition is a single-variable null / failure test
    /// (`if (!f)`, `f == NULL`, `fd < 0`, `err != nil`): the variable and
    /// which edge is its null edge.  `None` for any other condition shape.
    /// Consumed by the resource-lifecycle passes to prune the branch on which
    /// an acquire produced nothing.
    #[serde(default)]
    pub null_check: Option<NullCheck>,
    /// For If headers whose condition is a call (`if (fclose(f))`): that call
    /// as structured data.  The header node
    /// is not a `StmtKind::Call`, so the resource passes read this to apply
    /// the call's release effect, which runs before either branch.
    #[serde(default)]
    pub cond_call: Option<Box<CondCall>>,
    /// For Return nodes: variables (and member paths) the returned expression
    /// hands to the caller, in escape positions only (see
    /// `helpers::collect_return_escapes`).  `return f`, `return f, nil`,
    /// `return &W{f: f}` and `return new BufferedReader(r)` list `f` / `r`;
    /// `return f.read()` and `return io.ReadAll(f)` list nothing.  Consumed by
    /// the resource-leak passes as "ownership moved to the caller".
    #[serde(default)]
    pub returned_idents: Vec<String>,
    /// For Return nodes: callee text of each call / constructor whose result
    /// is itself the returned value (`return os.Open(p)`,
    /// `return new Foo()`), spelled like `CallMeta::callee`.
    #[serde(default)]
    pub returned_call_callees: Vec<String>,
    /// True for the node built from the last statement of a Ruby method
    /// body, whose value the method implicitly returns.  `returned_idents` /
    /// `returned_call_callees` then describe that value, exactly as they do
    /// for an explicit Return node.  The node keeps its own `StmtKind`.
    #[serde(default)]
    pub implicit_return: bool,
    /// True when this node's assignment stores into storage the body does
    /// not own as a plain local: through a pointer (`*out = v`), into a
    /// container element (`a[k] = v`, `$a[] = v`), or (C / C++ / Go / Java,
    /// where locals must be declared) into a name that is neither a
    /// parameter nor declared anywhere in the function: a global, a package
    /// variable, or an unqualified field / member.  The resource passes
    /// treat a handle stored this way as handed off, not as a new local
    /// resource that must be released before the function returns.
    #[serde(default)]
    pub escaping_store: bool,
    /// Shape of this C / C++ assignment's value; see [`RhsShape`].
    #[serde(default)]
    pub rhs_shape: RhsShape,
    /// Go: the variable this node defines has its address taken (`&p`) or is
    /// assigned inside a nested function literal, so it can change without
    /// an assignment the SSA form sees.  Abstract string facts that rest on
    /// the exclusion of characters (`Trim`, `ReplaceAll`) are not trusted for
    /// such a variable.
    #[serde(default)]
    pub aliased_def: bool,
    /// For If / conditional (ternary) nodes: the condition as a pure
    /// integer-arithmetic + comparison expression tree, when the whole
    /// condition is built only from integer literals, identifiers, arithmetic
    /// / comparison operators, and parentheses.  `None` for any condition that
    /// touches a call, field access, string, compound boolean (`&&`/`||`), or
    /// any shape this evaluator cannot prove constant.  Consumed by
    /// [`crate::ssa::const_prop::fold_constant_branches`] to prune branches
    /// whose condition folds to a definite boolean once its variables are
    /// resolved to constants — closing the synthetic "dead branch keeps the
    /// tainted phi operand alive" false positive without any text re-parsing.
    pub cond_arith: Option<CondArith>,
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
    /// Read-modify-write assignment (`x += y`, `$x .= $y`, `x ||= y`): the
    /// node defines its target and `taint.uses` starts with the target's own
    /// reads, so the new value depends on the old one.  SSA lowering uses
    /// this to keep the node from collapsing into a copy of its first
    /// operand when the right-hand side contributes no SSA value.
    #[serde(default)]
    pub rmw_assign: bool,
    /// Set on the combine node `x = x <op> <call result>` that
    /// `split_rmw_call` splits off a read-modify-write assignment whose
    /// right-hand side is a call.  The call result is the SSA value of the
    /// node's single CFG predecessor (the call node).
    #[serde(default)]
    pub rmw_rhs_from_pred: bool,
    /// Return node that leaves its function through the `finally` / `ensure`
    /// clause of an enclosing try.  It keeps one Seq edge into the clause's
    /// early-exit copy instead of the usual edge to the function exit, and
    /// SSA lowering keeps that edge as a block successor of the return.
    /// See `blocks::build_finally_paths`.
    #[serde(default)]
    pub finally_return: bool,
    /// Synthetic Return that ends an early-exit copy of a `finally` /
    /// `ensure` clause.  It stands for the returns the copy was entered from
    /// and carries the union of their uses.  SSA lowers it as
    /// `Terminator::Unreachable`: the value was already returned at the
    /// original Return block.
    #[serde(default)]
    pub finally_tail: bool,
    /// True when this acquisition node is inside a language-managed cleanup
    /// scope (Python `with`, Java try-with-resources, C# `using`).
    /// Only meaningful on Call nodes that define a resource variable.
    /// Leak detectors check this flag on the acquire site, not the variable.
    pub managed_resource: bool,
    /// True when this is a Java `X.getConnection()` acquire whose receiver
    /// `X` has a statically-declared *borrowed-owner* type — a managed
    /// session / DB abstraction (Liquibase `Database`, Hibernate `Session`,
    /// MyBatis `SqlSession`, JPA `EntityManager`) that closes the connection
    /// as part of its own lifecycle.  The borrowing body must NOT close it,
    /// so a leak-at-exit finding on such an acquire is a false positive.
    /// `DataSource` / static `DriverManager` `getConnection(...)` return an
    /// OWNED connection the caller must close (this stays `false` — those
    /// leaks are real).  Set only at CFG build for Java (see
    /// `java_getconnection_receiver_is_borrowed`); consumed by the
    /// `state-resource-leak` and `cfg-resource-leak` passes.
    #[serde(default)]
    pub borrowed_resource: bool,
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
    /// Same call shape as [`Self::parameterized_query`] (SQL_QUERY sink, query
    /// text plus a params argument, a placeholder in the text), but the query
    /// text is itself interpolated (`f"... {sort} LIMIT ?"`, Ruby
    /// `"... #{q} ... = ?"`, JS `` `... ${t} ... $1` ``).  The sink is kept
    /// and `sink_payload_args` narrows to the query text, since the bound
    /// params are never the injection vector.  The structural
    /// `cfg-unguarded-sink` pass only reports these when taint reaches arg 0.
    #[serde(default)]
    pub parameterized_query_interpolated: bool,
    /// Constant leading string prefix recovered from the node's RHS when it
    /// is a template literal (JS/TS) with a leading `string_fragment` or an
    /// equivalent constant-string-then-interpolation shape.  Populated for
    /// assignment-like nodes (`variable_declarator`, `assignment_expression`,
    /// `lexical_declaration`).  Consumed by the abstract string domain in
    /// `transfer_abstract` to seed a `StringFact::from_prefix` on the result
    /// SSA value so SSRF prefix-suppression can fire for values constructed
    /// from template literals.
    pub string_prefix: Option<String>,
    /// True when this node's RHS is exactly `<string literal> + <operand>`
    /// with a bare identifier or a single call as the operand, and
    /// [`Self::string_prefix`] is that whole literal.  The result's string
    /// fact is then the literal concatenated with the operand's fact (a
    /// `"/" + strings.Trim(p, "/\\")` tail still says which character
    /// follows the `/`), not just the literal prefix.  Go only for now.
    #[serde(default)]
    pub string_concat_tail: bool,
    /// `(identifier, literal tail)` when the string this node builds starts
    /// with a bare identifier instead of a literal (`API + p`,
    /// `` `${API}/x/${id}` ``).  Resolved into [`Self::string_prefix`] at the
    /// end of `build_cfg` when the identifier is a module-level string
    /// constant; cleared there either way, so it is never serialized.
    #[serde(skip)]
    pub string_prefix_ident: Option<(String, String)>,
    /// For If nodes whose condition is a prefix test against a bare
    /// identifier (`p.startswith(ROOT)`): true when that identifier resolves
    /// to a constant that is provably not separator-terminated, so the test
    /// also admits a sibling directory sharing the prefix.  Set at the end of
    /// `build_cfg` by `module_consts::resolve_root_idents`.
    #[serde(skip)]
    pub root_unterminated: bool,
    /// True when this node is a binary equality/inequality expression whose
    /// operator is `==` / `!=` / `===` / `!==` and exactly one operand is a
    /// syntactic literal (string / number / null / boolean). The SSA taint
    /// transfer uses this to suppress boolean-result taint propagation: the
    /// boolean outcome of `x === 'literal'` carries no attacker-controlled
    /// data, so downstream branches on it should not inherit x's caps.
    pub is_eq_with_const: bool,
    /// True when this assignment's right-hand side is a PHP numeric
    /// conversion (`(int)`, `(float)`, `(bool)` cast) or an arithmetic
    /// expression (`-`, `*`, `/`, `%`, `**`). PHP evaluates those to a
    /// number (or throws), so the stored value cannot carry injection
    /// payload and the SSA taint transfer clears its caps, like `intval`.
    #[serde(default)]
    pub yields_number: bool,
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
    /// Declared type annotation of a `let x: T = <rhs>` binding, lowered to
    /// the lattice [`crate::ssa::type_facts::TypeKind`] it denotes.  Rust
    /// only (the sole language whose binding RHS — `str::parse` — is
    /// ambiguous between numeric and non-numeric `FromStr` targets).
    /// Consumed by [`crate::ssa::type_facts`] as a high-priority override on
    /// the bound value's type: `let p: PathBuf = s.parse()?` → `Object`
    /// (recall — FILE_IO fires) while `let port: u16 = s.parse()?` → `Int`
    /// (precision — numeric shell arg stays suppressed).  `None` for
    /// un-annotated bindings, non-`let` nodes, and unrecognised annotation
    /// types, so the conservative bare-`parse` → `Int` default is preserved.
    #[serde(default)]
    pub decl_type: Option<crate::ssa::type_facts::TypeKind>,
    /// Value-use identifiers in this (sink) node whose **every** syntactic
    /// occurrence is consumed by a numeric- or safe-string-producing call
    /// (`x.parse::<u16>()`, `parseInt(x)`, `Atoi(x)`, `Integer.toString(x)`,
    /// …).  Such an identifier reaches the node only as a number (or a
    /// number stringified by an injection-free converter), so it cannot
    /// carry CRLF / `..` / quote / shell metacharacters at a
    /// type-suppressible sink.
    ///
    /// This is the inline-chain analogue of the value-level
    /// [`crate::ssa::type_facts::TypeKind::Int`] suppression: an expression
    /// like `sink(s.parse::<u16>().unwrap().to_string())` /
    /// `read(format!("/d/{}", s.parse::<u32>()))` never lowers its inner
    /// numeric chain to a dedicated SSA value (the outer call/macro flattens
    /// the tainted source leaf `s` directly into its use set), so there is no
    /// intermediate value to carry the `Int` fact.  Recovered here at CFG
    /// construction by an AST walk (`collect_numeric_confined_value_idents`)
    /// and consumed by the SSA taint sink-event collector to drop the
    /// confined leaf.  Soundness: an identifier that *also* appears raw
    /// anywhere in the node is **not** listed (a single un-wrapped occurrence
    /// blocks confinement), so a real injection through the same variable
    /// still fires.
    #[serde(default)]
    pub numeric_confined_uses: Vec<String>,

    /// Syntactic phantom identifiers lifted from a Rust `format!`-family
    /// macro's flattened `token_tree` — the macro name (`format`) and the
    /// method-name tokens (`parse`, `unwrap`, …) of a *numeric-confined*
    /// interpolation argument.  tree-sitter-rust models macro arguments as a
    /// flat token run, so `g.parse::<u32>().unwrap()` contributes `g`, `parse`,
    /// and `unwrap` as bare-identifier uses; only `g` is a real value.  Recorded
    /// here so the structural `cfg-unguarded-sink` confinement check
    /// ([`crate::cfg_analysis`]) can skip these non-value SSA `Param`
    /// operands (the SSA-taint side ignores them automatically — they are never
    /// tainted).  Empty unless [`Self::numeric_confined_uses`] is non-empty for
    /// a Rust format-macro sink, so non-format nodes are unperturbed.
    #[serde(default)]
    pub format_macro_method_idents: Vec<String>,

    /// Go map-membership lookup bound to a boolean result: `_, ok := m[k]`,
    /// `v, ok := m[k]`, or `ok := m[k]` on a `map[K]bool`.  Lets the taint
    /// engine treat `if !ok { return }` as the same allowlist check as the
    /// inline `if !m[k] { return }`.  `None` everywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_lookup: Option<MembershipLookup>,

    /// True for the `If` node `build_ternary_diamond` creates for the
    /// condition of `x = c ? a : b` / `x = a if c else b`.  Both arms yield
    /// a value, so rules about a branch that should have returned
    /// (`cfg-error-fallthrough`) do not apply to it.
    #[serde(default)]
    pub is_ternary_condition: bool,
    /// For an assignment whose whole right-hand side is a subscript read
    /// `container[key]` of a plain-identifier container (`user = repos[name]`):
    /// the text of the key.  The key picks which element is read; it is not
    /// part of the value, so the taint transfer leaves the key operand out of
    /// the result and takes taint from the container only.  `None` for every
    /// other node.
    #[serde(default)]
    pub index_read_key: Option<Box<str>>,
    /// Go only: constant-index element reads `base[3]` this node performs on a
    /// plain identifier, spelled `base[3]`, where `base` is read nowhere else
    /// in the node.  SSA lowering gives each one a value of its own (one per
    /// version of `base`), so a check on `parts[0]` and a later read of
    /// `parts[0]` talk about the same value, as they would for `k := parts[0]`.
    /// Empty for every other node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub elem_reads: Vec<Box<str>>,
    /// Go only: some base named in [`Self::elem_reads`] can be written other
    /// than by redefining it (an indexed store, `sort.Strings(b)`, `copy(b, x)`,
    /// `f(b)`, `p := &b`, `q := b`, a closure doing any of these), so a check
    /// on one of its elements does not hold for a later read of the same
    /// element and no element value is made for it.  Set after the whole file
    /// is built (see `mark_unstable_elem_bases`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub elem_base_unstable: bool,
    /// Go only: the map keys this statement adds to a named map, by
    /// `m[k] = v`, `m[k]++`, or a composite literal with variable keys
    /// (`m := map[string]bool{k: true}`).  The taint engine reads it to tell
    /// whether a map used as an allowlist can hold request-controlled keys.
    /// Empty for every other node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub map_stores: Vec<MapStore>,
}

/// One named map receiving keys; see [`NodeInfo::map_stores`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MapStore {
    /// The map; a bare identifier.
    pub base: String,
    /// Identifiers read by the key expression (empty for a literal key).
    pub key_idents: Vec<String>,
}

/// A `map[key]` read whose presence result lands in `result_var`.  See
/// [`NodeInfo::membership_lookup`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MembershipLookup {
    /// Variable holding the presence boolean (`ok`).
    pub result_var: String,
    /// The map being indexed; a bare identifier.
    pub base: String,
    /// The key under test: a bare identifier, or a constant-index element
    /// read spelled `parts[0]`.
    pub key: String,
    /// The value binding of the two-target form (`v` in `v, ok := m[k]`).
    pub value_var: Option<String>,
    /// Go: the map is not defined by the function holding the lookup (a
    /// package-level map) and another function of the file stores a
    /// non-literal key into it, so it may hold request-controlled keys.  Set
    /// after every body is built (see `mark_shared_map_lookups`).
    #[serde(default)]
    pub filled_elsewhere: bool,
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
    pub entry: NodeIndex,
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

// Per-body CFG types

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
    /// Per-formal request-binding flag. Same length as `params`.
    /// For Python and Ruby, `true` at position `i` iff the formal name
    /// appears as a path capture in a framework routing decorator on this
    /// function (Flask `@app.route("/users/<name>")`, blueprint-prefixed
    /// `@bp.get("/u/<int:id>")`, FastAPI / Starlette verb decorators,
    /// Sinatra `:name` segments). For Java, `true` iff the formal carries a
    /// Spring / JAX-RS binding annotation or has a non-infrastructure type
    /// (see `params::java_formal_is_request_bound`). For TypeScript, `true`
    /// iff the formal carries a request-binding parameter decorator (NestJS
    /// `@Query('q') q`, `@Body() dto`). The entry-kind seeding pass consults
    /// this so only request-bound formals (not implicit globals, DI handles
    /// or injected response / session objects) are painted as adversary
    /// input, and the JS/TS handler-param auto-seed paints the decorated
    /// TypeScript formals. Empty for top-level bodies.
    pub param_route_capture: Vec<bool>,
    /// JS/TS only: names this body binds itself, namely its formals plus
    /// every `var` / `let` / `const` / destructured binding, function or
    /// class declaration, `catch` parameter and `for-in` / `for-of` loop
    /// variable in its own scope (nested functions excluded, their bindings
    /// belong to them).  The two-level JS/TS solve consults it to keep a
    /// body's locals out of the top-level seed: only writes to names the
    /// body does not bind (module-level or captured variables) leave the
    /// body.  Sorted and deduplicated; empty for other languages.
    pub declared_names: Vec<String>,
}

/// A single executable body's CFG plus metadata.
#[derive(Debug)]
pub struct BodyCfg {
    pub meta: BodyMeta,
    pub graph: Cfg,
    pub entry: NodeIndex,
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
    /// Built once during JS/TS CFG construction. For Python it maps a bound
    /// name to the dotted path it names instead (`from M import n as a`
    /// gives `a` → `M.n`), which label classification uses to also try the
    /// qualified callee. Empty for other langs.
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
) -> (
    Option<String>,
    Vec<String>,
    bool,
    Option<CondArith>,
    Option<NullCheck>,
) {
    // 1. Find the condition subtree.
    let Some(cond) = find_condition_subtree(ast, lang) else {
        return (None, Vec::new(), false, None, None);
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

    // 5. Capture the pure integer-arithmetic + comparison tree (for constant
    //    branch folding).  Built from the FULL condition node `cond` (not the
    //    negation-stripped `inner`) so the folded boolean matches the
    //    Branch terminator's `true_blk = cond-true` semantics directly.  Ruby
    //    `unless` swaps the True/False edges in the CFG builder (lines
    //    ~5029), so the branch polarity would be inverted — skip it to stay
    //    sound (`unless` with a constant arithmetic guard is negligible).
    let cond_arith = if ast.fkind() == "unless" {
        None
    } else {
        build_cond_arith(cond, lang, code, 0)
    };

    // 6. Single-variable null / failure test (`if (!f)`, `f == NULL`,
    //    `err != nil`).  Skipped for Ruby `unless` for the same reason as
    //    `cond_arith` above.
    let null_check = if ast.fkind() == "unless" {
        None
    } else {
        extract_null_check(cond, lang, code)
    };

    (text, vars, negated, cond_arith, null_check)
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
    let cond = if cond.fkind() == "parenthesized_expression" {
        cond.child_by_field_name("expression")
            .or_else(|| {
                let mut cursor = cond.walk();
                cond.children(&mut cursor)
                    .find(|c| c.fkind() != "(" && c.fkind() != ")")
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
        cond.fkind(),
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
            .is_some_and(|c| c.fkind() == "!" || c.fkind() == "not");

        if has_not {
            // Return the operand (inner expression after the `!` / `not`).
            let inner = cond
                .child_by_field_name("argument")
                .or_else(|| cond.child_by_field_name("operand"))
                .or_else(|| {
                    // Last non-operator child.
                    let mut cursor = cond.walk();
                    cond.children(&mut cursor)
                        .filter(|c| c.fkind() != "!" && c.fkind() != "not")
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
        let kind = child.fkind();
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

/// Arithmetic operator of a read-modify-write assignment, taken from its
/// operator token and never from a binary expression inside the right-hand
/// side (`s += a - b` is an `Add`, not a `Sub`).
///
/// `None` for operators without an integer `BinOp` (`.=`, `||=`, `??=`,
/// `**=`, `>>>=`, `//=`) and for operators Python and Ruby overload on
/// strings, paths and collections: `*=` (repetition), `%=` (formatting),
/// `/=` (`pathlib` join), `|=` / `&=` / `^=` (set and dict merge) and Ruby
/// `<<=` (append).  A `BinOp` other than `Add` types the result `Int`,
/// which would hide a string payload from type-suppressible sinks.
fn rmw_bin_op(op: &str, lang: &str) -> Option<BinOp> {
    let overloaded = matches!(lang, "python" | "ruby");
    match op {
        "+=" | "++" => Some(BinOp::Add),
        "-=" | "--" => Some(BinOp::Sub),
        ">>=" => Some(BinOp::RightShift),
        "<<=" if lang != "ruby" => Some(BinOp::LeftShift),
        _ if overloaded => None,
        "*=" => Some(BinOp::Mul),
        "/=" => Some(BinOp::Div),
        "%=" => Some(BinOp::Mod),
        "&=" => Some(BinOp::BitAnd),
        "|=" => Some(BinOp::BitOr),
        "^=" => Some(BinOp::BitXor),
        _ => None,
    }
}

/// Integer operand of a read-modify-write assignment: `1` for `++` / `--`,
/// otherwise an integer-literal right-hand side.  Only meaningful when
/// [`rmw_bin_op`] yields an operator.
fn rmw_bin_op_const(rmw: &RmwAssign, code: &[u8]) -> Option<i64> {
    let rhs = match rmw.value {
        None => return Some(1),
        Some(rhs) => rhs,
    };
    // Go wraps both sides of `x += 1` in a one-element `expression_list`.
    let rhs = if rhs.fkind() == "expression_list" && rhs.named_child_count() == 1 {
        rhs.named_child(0)?
    } else {
        rhs
    };
    parse_int_literal(unwrap_parens(rhs), code)
}

/// Parse an integer literal node to its `i64` value, honouring hex / octal /
/// binary radix prefixes and Java/Rust digit separators (`1_000`).  Returns
/// `None` for floats, non-literals, or values that overflow `i64`.
fn parse_int_literal(node: Node, code: &[u8]) -> Option<i64> {
    let kind = node.fkind();
    let is_int = matches!(
        kind,
        "integer"
            | "integer_literal"
            | "int_literal"
            | "number"
            | "number_literal"
            | "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
    );
    if !is_int {
        return None;
    }
    let raw = slice_str(code, node.start_byte(), node.end_byte())?.trim();
    // Strip Java long suffix and digit separators.
    let cleaned: String = raw
        .trim_end_matches(['l', 'L'])
        .chars()
        .filter(|c| *c != '_')
        .collect();
    if let Ok(v) = cleaned.parse::<i64>() {
        return Some(v);
    }
    if let Some(h) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        return i64::from_str_radix(h, 16).ok();
    }
    if let Some(o) = cleaned
        .strip_prefix("0o")
        .or_else(|| cleaned.strip_prefix("0O"))
    {
        return i64::from_str_radix(o, 8).ok();
    }
    if let Some(b) = cleaned
        .strip_prefix("0b")
        .or_else(|| cleaned.strip_prefix("0B"))
    {
        return i64::from_str_radix(b, 2).ok();
    }
    None
}

/// Map the operator token of a binary expression node to a [`BinOp`].
/// Scans for the single anonymous operator child (operands are named).
/// Returns `None` for boolean operators (`&&` / `||`), assignment, or any
/// token not in the arithmetic / bitwise / comparison set — those make the
/// enclosing [`CondArith`] build bail.
fn binary_op_token(node: Node) -> Option<BinOp> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            continue;
        }
        return match child.fkind() {
            "+" => Some(BinOp::Add),
            "-" => Some(BinOp::Sub),
            "*" => Some(BinOp::Mul),
            "/" => Some(BinOp::Div),
            "%" => Some(BinOp::Mod),
            "&" => Some(BinOp::BitAnd),
            "|" => Some(BinOp::BitOr),
            "^" => Some(BinOp::BitXor),
            "<<" => Some(BinOp::LeftShift),
            ">>" => Some(BinOp::RightShift),
            "==" | "===" => Some(BinOp::Eq),
            "!=" | "!==" => Some(BinOp::NotEq),
            "<" => Some(BinOp::Lt),
            "<=" => Some(BinOp::LtEq),
            ">" => Some(BinOp::Gt),
            ">=" => Some(BinOp::GtEq),
            _ => None,
        };
    }
    None
}

/// Build a [`CondArith`] tree from a condition AST subtree, or `None` if the
/// condition is not a pure integer-arithmetic + comparison expression.  Uses
/// the real tree-sitter node so operator precedence and parentheses are
/// already encoded in the tree shape — no text parsing.  Conservative by
/// construction: any unrecognised node kind (call, field access, string,
/// boolean `&&`/`||`, unary `!`) returns `None`, which disables folding for
/// that branch (never a wrong fold).  Depth-bounded to guard against
/// pathological nesting.
pub(super) fn build_cond_arith(
    node: Node,
    lang: &str,
    code: &[u8],
    depth: u32,
) -> Option<CondArith> {
    if depth > 64 {
        return None;
    }
    let kind = node.fkind();

    // Unwrap parentheses (transparent to value).
    if matches!(
        kind,
        "parenthesized_expression" | "parenthesized" | "parenthesized_statement"
    ) {
        let inner = node.named_child(0)?;
        return build_cond_arith(inner, lang, code, depth + 1);
    }

    if let Some(n) = parse_int_literal(node, code) {
        return Some(CondArith::Lit(n));
    }

    // Bare identifier (reject dotted paths / field access — those are not
    // captured here; only a plain local whose const value we can resolve).
    if matches!(kind, "identifier" | "simple_identifier") {
        let name = text_of(node, code)?;
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
        {
            return Some(CondArith::Var(name));
        }
        return None;
    }

    // Unary `-` only (boolean `!` / `not` is intentionally unsupported: its
    // operand would be a boolean, which `CondArith::eval` rejects, so folding
    // a negated condition is left to the conservative `None` path).
    if matches!(
        kind,
        "unary_expression" | "unary_operator" | "prefix_unary_expression" | "unary"
    ) {
        let operand = node.named_child(0)?;
        let mut cursor = node.walk();
        let is_neg = node
            .children(&mut cursor)
            .any(|c| !c.is_named() && c.fkind() == "-");
        if is_neg {
            return Some(CondArith::Neg(Box::new(build_cond_arith(
                operand,
                lang,
                code,
                depth + 1,
            )?)));
        }
        return None;
    }

    // Binary arithmetic / comparison: exactly two operands + one operator.
    if is_binary_expr_kind(kind, lang) {
        if node.named_child_count() != 2 {
            return None; // chained comparison (Python `a < b < c`) etc.
        }
        let op = binary_op_token(node)?;
        let lhs = build_cond_arith(node.named_child(0)?, lang, code, depth + 1)?;
        let rhs = build_cond_arith(node.named_child(1)?, lang, code, depth + 1)?;
        return Some(CondArith::Bin(op, Box::new(lhs), Box::new(rhs)));
    }

    None
}

/// Find the RHS value node of an assignment-like AST node (variable declarator,
/// lexical declaration, assignment expression). Used by helpers that need to
/// inspect what an identifier is being initialized to.
/// Key text of `container[key]` when `ast` is a plain assignment or
/// declaration whose entire right-hand side is that subscript read (see
/// [`NodeInfo::index_read_key`]).  The kind check comes first so ordinary
/// nodes pay one string match.
fn plain_index_read_key(ast: Node, code: &[u8]) -> Option<Box<str>> {
    let assign = match ast.fkind() {
        "variable_declarator"
        | "assignment_expression"
        | "assignment"
        | "lexical_declaration"
        | "variable_declaration" => ast,
        "expression_statement" => ast
            .named_child(0)
            .filter(|c| matches!(c.fkind(), "assignment_expression" | "assignment"))?,
        _ => return None,
    };
    let mut rhs = assignment_rhs(assign)?;
    while matches!(
        rhs.fkind(),
        "parenthesized_expression" | "non_null_expression" | "as_expression"
    ) {
        rhs = rhs.named_child(0)?;
    }
    let (arr, key) = subscript_components(rhs, code)?;
    (arr != key).then(|| key.into_boxed_str())
}

/// Keys stored into named maps by a Go statement (see
/// [`NodeInfo::map_stores`]).
fn go_map_stores(ast: Node, code: &[u8]) -> Vec<MapStore> {
    let mut out = Vec::new();
    let mut push_index = |n: Node| {
        if n.fkind() == "index_expression"
            && let (Some(op), Some(ix)) = (
                n.child_by_field_name("operand"),
                n.child_by_field_name("index"),
            )
            && op.fkind() == "identifier"
            && let Some(base) = text_of(op, code)
        {
            let mut key_idents = Vec::new();
            collect_idents(ix, code, &mut key_idents);
            out.push(MapStore { base, key_idents });
        }
    };
    match ast.fkind() {
        "assignment_statement" => {
            if let Some(left) = ast.child_by_field_name("left") {
                if left.fkind() == "expression_list" {
                    let mut c = left.walk();
                    for l in left.named_children(&mut c) {
                        push_index(l);
                    }
                } else {
                    push_index(left);
                }
            }
        }
        "inc_dec_statement" => {
            if let Some(op) = ast.named_child(0) {
                push_index(op);
            }
        }
        _ => {}
    }
    // `m := map[K]V{k: v}` / `m = map[K]V{k: v}` / `var m = map[K]V{k: v}`.
    let (names, values) = match ast.fkind() {
        "short_var_declaration" | "assignment_statement" => (
            ast.child_by_field_name("left"),
            ast.child_by_field_name("right"),
        ),
        "var_spec" => (
            ast.child_by_field_name("name"),
            ast.child_by_field_name("value"),
        ),
        _ => (None, None),
    };
    if let (Some(names), Some(values)) = (names, values)
        && let Some(base) = {
            let first = if names.fkind() == "expression_list" {
                names.named_child(0)
            } else {
                Some(names)
            };
            first
                .filter(|n| n.fkind() == "identifier")
                .and_then(|n| text_of(n, code))
        }
    {
        let lit = if values.fkind() == "expression_list" {
            values.named_child(0)
        } else {
            Some(values)
        };
        if let Some(lit) = lit.filter(|l| l.fkind() == "composite_literal") {
            let mut stack = vec![lit];
            while let Some(n) = stack.pop() {
                if n.fkind() == "func_literal" {
                    continue;
                }
                if n.fkind() == "keyed_element"
                    && let Some(key) = n.named_child(0)
                {
                    let mut key_idents = Vec::new();
                    collect_idents(key, code, &mut key_idents);
                    if !key_idents.is_empty() {
                        out.push(MapStore {
                            base: base.clone(),
                            key_idents,
                        });
                    }
                }
                let mut c = n.walk();
                stack.extend(n.children(&mut c));
            }
        }
    }
    out
}

/// Go: how many statements of `func` (and of function literals nested in it)
/// define the plain identifier `base`.  More than one means a redefinition or
/// a shadowing declaration, so a guard on `base[0]` may name another variable
/// than the one a later read of `base[0]` does.
pub(crate) fn go_base_def_count(cfg: &Cfg, func: Option<&str>, base: &str) -> usize {
    let mut range: Option<(usize, usize)> = None;
    for n in cfg.node_weights() {
        if n.ast.enclosing_func.as_deref() == func {
            let (a, b) = n.ast.span;
            range = Some(match range {
                Some((lo, hi)) => (lo.min(a), hi.max(b)),
                None => (a, b),
            });
        }
    }
    let Some((lo, hi)) = range else {
        return 0;
    };
    cfg.node_weights()
        .filter(|n| {
            (n.ast.enclosing_func.as_deref() == func || (n.ast.span.0 >= lo && n.ast.span.1 <= hi))
                && (n.taint.defines.as_deref() == Some(base)
                    || n.taint.extra_defines.iter().any(|d| d == base))
        })
        .count()
}

/// Whether this occurrence of the Go identifier `id` cannot write the array it
/// names: an element read, `len`/`cap`, ranging over it, or (re)defining the
/// variable itself.
fn go_base_use_is_benign(id: Node, code: &[u8]) -> bool {
    let Some(p) = id.parent() else {
        return false;
    };
    let is_left = |owner: Node, child: Node| {
        owner
            .child_by_field_name("left")
            .is_some_and(|l| l.id() == child.id())
    };
    match p.fkind() {
        "index_expression" => {
            if p.child_by_field_name("operand").map(|o| o.id()) != Some(id.id()) {
                return false;
            }
            // A target list `a[0], b = ...` wraps the element in an expression_list.
            let mut anc = p;
            if let Some(list) = p.parent().filter(|l| l.fkind() == "expression_list") {
                anc = list;
            }
            match anc.parent() {
                Some(g) if g.fkind() == "assignment_statement" => !is_left(g, anc),
                Some(g) if g.fkind() == "inc_dec_statement" => false,
                // `&parts[0]` hands out a pointer to the element.
                Some(g) if g.fkind() == "unary_expression" => {
                    g.child(0).is_some_and(|op| op.fkind() != "&")
                }
                _ => true,
            }
        }
        "argument_list" => p
            .parent()
            .filter(|c| c.fkind() == "call_expression")
            .and_then(|c| c.child_by_field_name("function"))
            .filter(|f| f.fkind() == "identifier")
            .and_then(|f| text_of(f, code))
            .is_some_and(|f| matches!(f.as_str(), "len" | "cap")),
        "short_var_declaration" | "assignment_statement" => is_left(p, id),
        "expression_list" => p.parent().is_some_and(|g| {
            matches!(
                g.fkind(),
                "short_var_declaration" | "assignment_statement" | "range_clause"
            ) && is_left(g, p)
        }),
        "range_clause" => true,
        "var_spec" | "parameter_declaration" => true,
        _ => false,
    }
}

/// Set [`NodeInfo::elem_base_unstable`] on every Go node that reads a
/// constant-index element of a base the enclosing function can write through
/// another route.  Runs once per Go file and only when such reads exist; the
/// function is walked once per distinct base.
fn mark_unstable_elem_bases(bodies: &mut [BodyCfg], root: Node, code: &[u8]) {
    let mut targets: Vec<(usize, petgraph::graph::NodeIndex)> = Vec::new();
    for (i, b) in bodies.iter().enumerate() {
        for idx in b.graph.node_indices() {
            if !b.graph[idx].elem_reads.is_empty() {
                targets.push((i, idx));
            }
        }
    }
    if targets.is_empty() {
        return;
    }
    let mut cache: HashMap<(usize, usize, String), bool> = HashMap::new();
    for (i, idx) in targets {
        let info = &bodies[i].graph[idx];
        let (lo, hi) = info.ast.span;
        let bases: Vec<String> = info
            .elem_reads
            .iter()
            .filter_map(|e| e.split_once('[').map(|(b, _)| b.to_string()))
            .collect();
        // Outermost function around the read; closures sit inside it.
        let mut func = root;
        if let Some(mut n) = root.descendant_for_byte_range(lo, hi) {
            let mut outer = None;
            loop {
                if matches!(
                    n.fkind(),
                    "function_declaration" | "method_declaration" | "func_literal"
                ) {
                    outer = Some(n);
                }
                match n.parent() {
                    Some(p) => n = p,
                    None => break,
                }
            }
            func = outer.unwrap_or(root);
        }
        let key = (func.start_byte(), func.end_byte());
        let mut unstable = false;
        for base in bases {
            let u = *cache
                .entry((key.0, key.1, base.clone()))
                .or_insert_with(|| {
                    let mut stack = vec![func];
                    while let Some(n) = stack.pop() {
                        if n.fkind() == "identifier"
                            && text_of(n, code).as_deref() == Some(base.as_str())
                            && !go_base_use_is_benign(n, code)
                        {
                            return true;
                        }
                        let mut c = n.walk();
                        stack.extend(n.children(&mut c));
                    }
                    false
                });
            unstable |= u;
        }
        if unstable {
            bodies[i].graph[idx].elem_base_unstable = true;
        }
    }
}

/// `base[idx]` spelling of a constant-index element read, when `idx` is a
/// plain decimal literal and `base` a bare identifier.
fn const_index_name(base: &str, idx: &str) -> Option<String> {
    let plain_base =
        !base.is_empty() && base.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
    let plain_idx = idx.len() <= 4
        && idx.bytes().all(|c| c.is_ascii_digit())
        && (idx == "0" || !idx.starts_with('0'));
    (plain_base && plain_idx).then(|| format!("{base}[{idx}]"))
}

/// Constant-index element reads in a Go expression or statement (see
/// [`NodeInfo::elem_reads`]).  Only `ident[<decimal literal>]` counts, and only
/// when the identifier is not read any other way in the same subtree, because
/// lowering swaps the base operand for the element value.  Assignment targets
/// are writes and are left out; function literals are separate bodies.
fn go_const_index_reads(root: Node, code: &[u8]) -> Vec<Box<str>> {
    // Only `ident[<decimal literal>]` counts, so a `[` directly followed by a
    // digit is a sound witness; slices, maps and generics skip the walk.
    if !code
        .get(root.start_byte()..root.end_byte())
        .is_some_and(|b| b.windows(2).any(|w| w[0] == b'[' && w[1].is_ascii_digit()))
    {
        return Vec::new();
    }
    let start = if matches!(
        root.fkind(),
        "assignment_statement" | "short_var_declaration"
    ) {
        match root.child_by_field_name("right") {
            Some(r) => r,
            None => return Vec::new(),
        }
    } else {
        root
    };
    let mut elems: Vec<String> = Vec::new();
    let mut bare: Vec<String> = Vec::new();
    let mut stack = vec![start];
    while let Some(n) = stack.pop() {
        match n.fkind() {
            "func_literal" => continue,
            "identifier" => {
                if let Some(t) = text_of(n, code) {
                    bare.push(t);
                }
                continue;
            }
            "index_expression" => {
                if let (Some(op), Some(ix)) = (
                    n.child_by_field_name("operand"),
                    n.child_by_field_name("index"),
                ) && op.fkind() == "identifier"
                    && ix.fkind() == "int_literal"
                    && let (Some(b), Some(i)) = (text_of(op, code), text_of(ix, code))
                    && let Some(name) = const_index_name(&b, &i)
                {
                    elems.push(name);
                    continue;
                }
            }
            _ => {}
        }
        let mut c = n.walk();
        stack.extend(n.children(&mut c));
    }
    elems.sort();
    elems.dedup();
    elems
        .into_iter()
        .filter(|e| {
            let base = e.split_once('[').map_or(e.as_str(), |(b, _)| b);
            !bare.iter().any(|b| b == base)
        })
        .map(String::into_boxed_str)
        .collect()
}

/// The subtree [`go_const_index_reads`] should scan for a CFG node, or `None`
/// for node kinds that never carry such reads.  An `if` node reads only its
/// condition; its body is built from separate nodes.
fn go_elem_read_scope<'a>(ast: Node<'a>, is_if: bool) -> Option<Node<'a>> {
    if is_if {
        return helpers::find_condition_subtree(ast, "go");
    }
    matches!(
        ast.fkind(),
        "short_var_declaration"
            | "assignment_statement"
            | "var_declaration"
            | "expression_statement"
            | "return_statement"
            | "go_statement"
            | "defer_statement"
            | "call_expression"
            | "binary_expression"
            | "unary_expression"
            | "parenthesized_expression"
    )
    .then_some(ast)
}

fn assignment_rhs<'a>(ast: Node<'a>) -> Option<Node<'a>> {
    match ast.fkind() {
        // Go `x = ...` is an `assignment_statement` whose value sits on the
        // `right` expression list.
        "variable_declarator" | "assignment_expression" | "assignment" | "assignment_statement" => {
            ast.child_by_field_name("value")
                .or_else(|| ast.child_by_field_name("right"))
        }
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
        | "const_declaration"
        | "let_declaration" => {
            // Walk direct children for the first variable_declarator with a value.
            let mut w = ast.walk();
            ast.named_children(&mut w)
                .find(|c| c.fkind() == "variable_declarator")
                .and_then(|d| {
                    d.child_by_field_name("value")
                        .or_else(|| d.child_by_field_name("right"))
                })
                .or_else(|| {
                    // Go `var x = ...` / `const x = ...`: the value sits on
                    // the `var_spec` / `const_spec` child.
                    let mut w = ast.walk();
                    ast.named_children(&mut w)
                        .find(|c| matches!(c.fkind(), "var_spec" | "const_spec"))
                        .and_then(|spec| spec.child_by_field_name("value"))
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
            ast.named_children(&mut w).find_map(|c| match c.fkind() {
                "assignment_expression" | "assignment" => c
                    .child_by_field_name("right")
                    .or_else(|| c.child_by_field_name("value")),
                _ => None,
            })
        }
        _ => None,
    }
}

/// The operand of a Go `<string literal> + <operand>` right-hand side, with the
/// literal's whole text, when the operand is a bare identifier or a call.
/// The literal must hold no escape sequence so its text is its value.
fn go_literal_plus_operand<'a>(scope: Node<'a>, code: &[u8]) -> Option<(String, Node<'a>)> {
    fn unwrap<'t>(mut n: Node<'t>) -> Node<'t> {
        for _ in 0..4 {
            match n.fkind() {
                "parenthesized_expression" => match n.named_child(0) {
                    Some(c) => n = c,
                    None => return n,
                },
                "expression_list" if n.named_child_count() == 1 => match n.named_child(0) {
                    Some(c) => n = c,
                    None => return n,
                },
                _ => return n,
            }
        }
        n
    }
    if !matches!(
        scope.fkind(),
        "assignment_statement" | "short_var_declaration"
    ) {
        return None;
    }
    let rhs = unwrap(assignment_rhs(scope)?);
    if rhs.fkind() != "binary_expression" || rhs.child_by_field_name("operator")?.fkind() != "+" {
        return None;
    }
    let left = unwrap(rhs.child_by_field_name("left")?);
    if !matches!(
        left.fkind(),
        "interpreted_string_literal" | "raw_string_literal"
    ) {
        return None;
    }
    let text = text_of(left, code)?;
    let inner = text.get(1..text.len().checked_sub(1)?)?;
    if inner.is_empty() || inner.contains('\\') && left.fkind() == "interpreted_string_literal" {
        return None;
    }
    let operand = unwrap(rhs.child_by_field_name("right")?);
    matches!(operand.fkind(), "identifier" | "call_expression")
        .then(|| (inner.to_string(), operand))
}

/// Extract a constant leading string prefix from an assignment-like node's
/// RHS, or from the URL argument of a call, when it is a template literal,
/// f-string or interpolated string with a literal head, a `"lit" + x + y`
/// concatenation chain, or a format call (see [`prefix_of_expression`]).
/// Returns `None` if the grammar does not expose such a shape.
///
/// The recovered prefix is used by the abstract string domain to seed a
/// `StringFact::from_prefix` on the result SSA value. For SSRF detection,
/// when the prefix contains `scheme://host/`, the sink is suppressed because
/// the attacker cannot reach a different host.
///
/// `ops` are the node's [`url_operand_nodes`].
fn template_prefix_of(ops: &[(Node, bool)], lang: &str, code: &[u8]) -> Option<String> {
    ops.iter()
        .find_map(|&(n, _)| prefix_of_expression(n, lang, code))
}

/// The string-building operand a node's prefix is read from: an assignment's
/// RHS, then the URL argument of a call.  `url_arg` is the positional index of
/// the URL-bearing argument (the sink's single payload position, else `0`).
/// Empty for languages the prefix extractor does not cover.
fn url_operand_nodes<'t>(
    ast: Node<'t>,
    lang: &str,
    url_arg: usize,
) -> smallvec::SmallVec<[(Node<'t>, bool); 2]> {
    // Phase 14 — extended beyond JS/TS so the SSRF prefix-lock fires
    // across every supported language whose origin-locked URL shape
    // is a literal+tainted string concatenation.  The grammar
    // dispatch lives in [`prefix_of_expression`]; this function only
    // walks the assignment-RHS / URL call-arg slots that consume
    // the prefix.
    let supported = matches!(
        lang,
        "javascript" | "typescript" | "java" | "go" | "php" | "ruby" | "python" | "rust"
    );
    let mut out = smallvec::SmallVec::new();
    if !supported {
        return out;
    }

    // Assignment-like node: inspect the RHS directly.
    if let Some(rhs) = assignment_rhs(ast) {
        out.push((rhs, false));
    }

    // Call expression (including sink call nodes): inspect the URL argument.
    // Covers `axios.get(\`https://host/…${x}\`)` shape where the template
    // literal is inline at the sink.
    if matches!(
        ast.fkind(),
        "call_expression"
            | "call"
            | "new_expression"
            | "object_creation_expression"
            | "method_invocation"
            | "macro_invocation"
            | "function_call_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "nullsafe_member_call_expression"
    ) {
        let args = ast
            .child_by_field_name("arguments")
            .or_else(|| ast.child_by_field_name("argument_list"));
        if let Some(args_node) = args {
            // Express `res.redirect(301, url)`: skip a leading numeric
            // status so the URL argument's prefix is read.
            let status_first = url_arg == 0
                && args_node.named_child_count() == 2
                && args_node
                    .named_child(0)
                    .is_some_and(|status| is_numeric_literal_kind(status.fkind()));
            let url_node = args_node.named_child(if status_first { 1 } else { url_arg as u32 });
            out.extend(url_node.map(|n| (n, true)));
        }
    }
    out
}

/// Like [`template_prefix_of`] for a string that starts with a bare
/// identifier instead of a literal: `(name, literal tail)` for `API + p`,
/// `` `${API}/users/${id}` `` or `f"{API}/users/{id}"`.  The identifier is a
/// module-level constant candidate, resolved once every body of the file is
/// built (see `module_consts`).  When `url_sink` is set the URL argument may
/// also be the bare identifier itself (`requests.get(API, params=p)`).
fn lead_ident_of(
    ops: &[(Node, bool)],
    lang: &str,
    code: &[u8],
    url_sink: bool,
) -> Option<(String, String)> {
    ops.iter().find_map(|&(n, is_call_arg)| {
        lead_ident_of_operand(n, lang, code, is_call_arg && url_sink, !is_call_arg, 0)
    })
}

/// True for the node kinds that name a module-level constant visible inside
/// a function.  A lowercase Ruby name at file level is a local of the
/// top-level scope, which a `def` body does not see (there it is a method
/// call), so Ruby only resolves `constant` names.
fn is_identifier_kind(kind: &str, lang: &str) -> bool {
    match lang {
        "ruby" => kind == "constant",
        _ => kind == "identifier",
    }
}

/// The leading identifier of a string being built, with the literal text that
/// follows it directly.  Mirrors the shapes [`prefix_of_operand`] reads a
/// literal head from.  `concat_operand` accepts a bare identifier as the
/// whole operand (left-hand side of a concatenation, or a URL argument).
/// `descend_calls` follows a call into its first argument, as
/// [`prefix_of_operand`] does for a statement's own call; an operand of a
/// concatenation is never followed into a call, whose result is not its
/// argument.
fn lead_ident_of_operand(
    node: Node,
    lang: &str,
    code: &[u8],
    concat_operand: bool,
    descend_calls: bool,
    depth: usize,
) -> Option<(String, String)> {
    if depth > PREFIX_WALK_DEPTH {
        return None;
    }
    let mut cur = node;
    for _ in 0..8 {
        match cur.fkind() {
            "parenthesized_expression" | "argument" => cur = cur.named_child(0)?,
            "expression_list" if cur.named_child_count() == 1 => cur = cur.named_child(0)?,
            "as_expression" | "type_assertion" | "satisfies_expression" | "non_null_expression" => {
                cur = cur
                    .child_by_field_name("expression")
                    .or_else(|| cur.named_child(0))?;
            }
            "await_expression" | "yield_expression" => cur = cur.named_child(0)?,
            "call_expression" | "call" | "new_expression" if descend_calls => {
                let args = cur
                    .child_by_field_name("arguments")
                    .or_else(|| cur.child_by_field_name("argument_list"))?;
                let mut w = args.walk();
                cur = args.named_children(&mut w).next()?;
            }
            _ => break,
        }
    }
    let kind = cur.fkind();
    if matches!(kind, "binary_expression" | "binary_operator" | "binary") {
        let left = cur.named_child(0)?;
        let mut w = cur.walk();
        let op = cur.children(&mut w).find(|c| !c.is_named())?;
        return match op.fkind() {
            "+" | "." => lead_ident_of_operand(left, lang, code, true, false, depth + 1),
            _ => None,
        };
    }
    if concat_operand && is_identifier_kind(kind, lang) {
        return Some((text_of(cur, code)?, String::new()));
    }
    if is_string_like_kind(kind) {
        return string_leading_ident(cur, lang, code);
    }
    None
}

/// `(identifier, following literal text)` when a string node opens with an
/// interpolation of a bare identifier (`${API}…`, `{API}…`, `#{API}…`).
fn string_leading_ident(node: Node, lang: &str, code: &[u8]) -> Option<(String, String)> {
    let mut w = node.walk();
    let mut children = node
        .named_children(&mut w)
        .filter(|c| c.fkind() != "string_start");
    let first = children.next()?;
    if !matches!(first.fkind(), "template_substitution" | "interpolation") {
        return None;
    }
    if first.named_child_count() != 1 {
        return None;
    }
    let inner = first.named_child(0)?;
    if !is_identifier_kind(inner.fkind(), lang) {
        return None;
    }
    let tail = children
        .next()
        .filter(|c| is_string_content_kind(c.fkind()) && c.fkind() != "escape_sequence")
        .and_then(|c| text_of(c, code))
        .unwrap_or_default();
    Some((text_of(inner, code)?, tail))
}

fn is_numeric_literal_kind(kind: &str) -> bool {
    matches!(kind, "number" | "integer")
}

/// Deepest AST nesting [`prefix_of_operand`] follows through wrappers and down
/// the left spine of a concatenation chain.
const PREFIX_WALK_DEPTH: usize = 32;

/// Return the leading constant string of `node`: the literal head of a
/// template literal, f-string or interpolated string, the left-most literal of
/// a `"lit" + x + y` / PHP `"lit" . $x` chain, the literal text before the
/// first directive of a format call (`fmt.Sprintf`, `String.format`,
/// `sprintf`, `"..." % x`, `"...".format(x)`), or a Rust `format!` head.  Used
/// by `template_prefix_of` for both assignment RHS and call arguments.
///
/// Also descends through `await` / `yield` wrappers and into the first
/// argument of a call expression, this covers the common sink shape
/// `await axios.get(\`https://host/…${x}\`)` where the template literal lives
/// inside a call inside an `await` wrapper.
fn prefix_of_expression(node: Node, lang: &str, code: &[u8]) -> Option<String> {
    prefix_of_operand(node, lang, code, false, true, 0)
}

/// [`prefix_of_expression`] for one argument of a call: the argument's own
/// value, so a call in it is read only when it is a format call.  The result
/// of any other call is not its first argument (`wrap("https://h/" + x)` can
/// return anything).
pub(super) fn arg_prefix_of_expression(node: Node, lang: &str, code: &[u8]) -> Option<String> {
    prefix_of_operand(node, lang, code, false, false, 0)
}

/// `plain_literal_ok` is set for the operand of a concatenation: a bare
/// literal is a prefix there (`"https://h/" + x`) but not on its own, where
/// it is just a constant and not a string being built.  `descend_calls`
/// follows a non-format call into its first argument, which only the
/// statement-level reading wants (see [`prefix_of_expression`]).
fn prefix_of_operand(
    node: Node,
    lang: &str,
    code: &[u8],
    plain_literal_ok: bool,
    descend_calls: bool,
    depth: usize,
) -> Option<String> {
    if depth > PREFIX_WALK_DEPTH {
        return None;
    }
    // Unwrap trivial wrappers (parentheses, TS `as` / type assertions,
    // await/yield, PHP `argument`, a single-element Go expression list).
    let mut cur = node;
    for _ in 0..8 {
        match cur.fkind() {
            "parenthesized_expression" | "argument" => {
                cur = cur.named_child(0)?;
            }
            "expression_list" if cur.named_child_count() == 1 => {
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
                if let Some(p) = format_call_prefix(cur, lang, code) {
                    return Some(p);
                }
                if !descend_calls {
                    return None;
                }
                // Descend into the first positional argument (e.g.
                // `axios.get(\`https://…${x}\`)`, the URL we want to lock
                // is the template-literal first argument of the call).
                let args = cur
                    .child_by_field_name("arguments")
                    .or_else(|| cur.child_by_field_name("argument_list"))?;
                let mut w = args.walk();
                cur = args.named_children(&mut w).next()?;
            }
            "function_call_expression" | "method_invocation" => {
                return format_call_prefix(cur, lang, code);
            }
            _ => break,
        }
    }

    let kind = cur.fkind();

    // `"scheme://host/" + x + "/y"` / PHP `"scheme://host/" . $x` /
    // `"scheme://host/%s" % x`.  The prefix is whatever the left-most operand
    // starts with, so a left-nested chain recurses down its left spine.
    if matches!(kind, "binary_expression" | "binary_operator" | "binary") {
        let left = cur.named_child(0)?;
        let mut w = cur.walk();
        let op = cur.children(&mut w).find(|c| !c.is_named())?;
        return match op.fkind() {
            "+" | "." => prefix_of_operand(left, lang, code, true, false, depth + 1),
            "%" if matches!(lang, "python" | "ruby") => {
                literal_format_prefix(left, code, '%', depth + 1)
            }
            _ => None,
        };
    }

    // Case 3: Rust `format!("scheme://host/{}", x)` macro invocation.
    // The first positional arg is the format string literal whose
    // leading literal text (up to the first `{`) is the locked prefix.
    if cur.fkind() == "macro_invocation" {
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
                if matches!(child.fkind(), "string_literal" | "raw_string_literal") {
                    first_string = Some(child);
                    break;
                }
                if child.fkind() == "token_tree" {
                    let mut ttw = child.walk();
                    for inner in child.named_children(&mut ttw) {
                        if matches!(inner.fkind(), "string_literal" | "raw_string_literal") {
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
                    .find(|c| c.fkind() == "string_content" || c.fkind() == "string_fragment")
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

    // String-like nodes: the literal text before the first interpolation.
    // JS/TS template literals, Python f-strings (`string` with an
    // `interpolation` child), Ruby `"#{x}"`, PHP `encapsed_string` and, as
    // the operand of a concatenation, plain literals.  A plain literal on
    // its own is just a constant, so it is not read as a prefix.
    if is_string_like_kind(kind) {
        if kind == "template_string" || plain_literal_ok || string_is_interpolated(cur) {
            return string_leading_content(cur, code);
        }
        return None;
    }

    None
}

fn is_string_like_kind(kind: &str) -> bool {
    matches!(
        kind,
        "template_string"
            | "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "encapsed_string"
    )
}

/// True for content-bearing children of a string node: literal text and
/// escape sequences, as opposed to an interpolation or a delimiter.
fn is_string_content_kind(kind: &str) -> bool {
    kind.ends_with("_content") || kind.ends_with("_fragment") || kind == "escape_sequence"
}

/// True when a string node holds an interpolation (`#{x}`, `{x}`, `${x}`,
/// PHP `$x` / `{$x}`) rather than only text.
fn string_is_interpolated(node: Node) -> bool {
    let mut w = node.walk();
    node.named_children(&mut w).any(|c| {
        let k = c.fkind();
        !is_string_content_kind(k) && k != "string_start" && k != "string_end"
    })
}

/// The literal text a string node starts with, up to its first interpolation
/// or escape sequence.  Delimiters (`"`, quote tokens, Python `string_start`)
/// are skipped; `None` when the string starts with an interpolation or is
/// empty.
fn string_leading_content(node: Node, code: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        let k = child.fkind();
        if k == "string_start" {
            continue;
        }
        if k == "string_end" || k == "escape_sequence" || !is_string_content_kind(k) {
            break;
        }
        out.push_str(&text_of(child, code)?);
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Literal head of the format string `node` up to its first `directive`
/// (`%` for printf-style formats, `{` for Python `str.format`).  A directive
/// at the very start leaves no prefix.
fn literal_format_prefix(node: Node, code: &[u8], directive: char, depth: usize) -> Option<String> {
    let mut cur = node;
    for _ in 0..4 {
        if matches!(cur.fkind(), "parenthesized_expression" | "argument") {
            cur = cur.named_child(0)?;
        }
    }
    if depth > PREFIX_WALK_DEPTH
        || !is_string_like_kind(cur.fkind())
        || cur.fkind() == "template_string"
    {
        return None;
    }
    let head = string_leading_content(cur, code)?;
    let head = match head.find(directive) {
        Some(i) => head[..i].to_string(),
        None => head,
    };
    if head.is_empty() { None } else { Some(head) }
}

/// Prefix of a call that builds a string from a literal format:
/// `fmt.Sprintf("https://h/%s", id)`, `String.format(...)`,
/// `"https://h/%s".formatted(id)`, PHP `sprintf`, Ruby `format` / `sprintf`
/// and Python `"https://h/{}".format(id)`.
fn format_call_prefix(call: Node, lang: &str, code: &[u8]) -> Option<String> {
    let args = call
        .child_by_field_name("arguments")
        .or_else(|| call.child_by_field_name("argument_list"))?;
    let head = std::str::from_utf8(code.get(call.start_byte()..args.start_byte())?)
        .ok()?
        .trim();
    let format_fn = match lang {
        "go" => head == "fmt.Sprintf",
        "java" => head == "String.format",
        "php" => head == "sprintf",
        "ruby" => matches!(
            head,
            "format" | "sprintf" | "Kernel.format" | "Kernel.sprintf"
        ),
        _ => false,
    };
    if format_fn {
        let first = args.named_child(0)?;
        return literal_format_prefix(first, code, '%', 0);
    }
    // `"literal".format(...)` (Python) / `"literal".formatted(...)` (Java):
    // the format string is the call's receiver.
    let receiver = call.child_by_field_name("object").or_else(|| {
        call.child_by_field_name("function")
            .filter(|f| f.fkind() == "attribute")
            .and_then(|f| f.child_by_field_name("object"))
    })?;
    match (lang, head.rsplit('.').next()) {
        ("python", Some("format")) => literal_format_prefix(receiver, code, '{', 0),
        ("java", Some("formatted")) => literal_format_prefix(receiver, code, '%', 0),
        _ => None,
    }
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
            .find(|c| c.fkind() == "token_tree")?
    };
    let first_ident_name = {
        let mut w = token_tree.walk();
        let mut found: Option<String> = None;
        for child in token_tree.named_children(&mut w) {
            match child.fkind() {
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
        if !matches!(child.fkind(), "const_item" | "static_item") {
            continue;
        }
        let name = child
            .child_by_field_name("name")
            .and_then(|n| text_of(n, code));
        if name.as_deref() != Some(first_ident_name.as_str()) {
            continue;
        }
        let value = child.child_by_field_name("value")?;
        let lit = if matches!(value.fkind(), "string_literal" | "raw_string_literal") {
            value
        } else {
            continue;
        };
        let mut iw = lit.walk();
        let frag_text = lit
            .named_children(&mut iw)
            .find(|c| c.fkind() == "string_content" || c.fkind() == "string_fragment")
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
        let kind = n.fkind();
        if kind == "number"
            || kind == "integer"
            || kind == "integer_literal"
            || kind == "number_literal"
            || kind == "float"
        {
            let text = slice_str(code, n.start_byte(), n.end_byte())?.trim();
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
    match node.fkind() {
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|c| is_boolean_eq_const_tree(c, lang)),
        "unary_expression" | "not_operator" => {
            // `!` / `not`, operator is an anonymous child; operand is the
            // single named child.
            let mut w = node.walk();
            let mut op_is_not = false;
            for child in node.children(&mut w) {
                if !child.is_named() && matches!(child.fkind(), "!" | "not") {
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
            if !is_binary_expr_kind(node.fkind(), lang) {
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
                    let left_lit = is_equality_literal_kind(left.fkind());
                    let right_lit = is_equality_literal_kind(right.fkind());
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
            return Some(child.fkind().to_string());
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
///
/// Shared with [`crate::ssa::type_facts::is_int_producing_callee`] so the
/// value-level grain (`int n = s.length();`) and the callee-text grain
/// (`String.valueOf(s.length())`) agree on the same narrow list.
pub(crate) fn is_numeric_length_property(name: &str) -> bool {
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
    extract_member_field_name(assignment_rhs_or_self(ast), code)
}

/// The value expression of a declaration / assignment statement, or `ast`
/// itself when it has none.  Pulled the same way by every detector that reads
/// the RHS so they look at the same node grain.
#[inline]
fn assignment_rhs_or_self(ast: Node) -> Node {
    ast.child_by_field_name("value")
        .or_else(|| ast.child_by_field_name("right"))
        .or_else(|| {
            let mut cursor = ast.walk();
            ast.named_children(&mut cursor)
                .find(|c| matches!(c.fkind(), "variable_declarator" | "init_declarator"))
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
                .find(|c| matches!(c.fkind(), "assignment"))
                .and_then(|a| a.child_by_field_name("right"))
        })
        .unwrap_or(ast)
}

/// See [`RhsShape`].
fn rhs_shape_of(ast: Node) -> RhsShape {
    let mut rhs = assignment_rhs_or_self(ast);
    if rhs.id() == ast.id() {
        // `expression_statement > assignment_expression`
        let mut cursor = ast.walk();
        let Some(inner) = ast
            .named_children(&mut cursor)
            .find(|c| c.fkind() == "assignment_expression")
            .and_then(|a| a.child_by_field_name("right"))
        else {
            return RhsShape::Whole;
        };
        rhs = inner;
    }
    let v = strip_parens_and_casts(rhs);
    if v.fkind() == "identifier" && unwrap_parens(rhs).fkind() == "cast_expression" {
        return RhsShape::CastView;
    }
    match v.fkind() {
        "initializer_list" | "compound_literal_expression" => RhsShape::Aggregate,
        "binary_expression" | "unary_expression" | "sizeof_expression" | "update_expression" => {
            RhsShape::SubObject
        }
        "pointer_expression" => {
            if v.child_by_field_name("operator")
                .is_some_and(|op| op.fkind() == "&")
            {
                RhsShape::SubObject
            } else {
                RhsShape::Projection
            }
        }
        "field_expression" | "subscript_expression" => RhsShape::Projection,
        // `c ? a : b` copies a handle only when a branch is one itself.
        "conditional_expression" => {
            let copies = ["consequence", "alternative"].iter().any(|f| {
                v.child_by_field_name(f).is_some_and(|n| {
                    matches!(
                        strip_parens_and_casts(n).fkind(),
                        "identifier" | "this" | "conditional_expression"
                    )
                })
            });
            if copies {
                RhsShape::Whole
            } else {
                RhsShape::SubObject
            }
        }
        _ => RhsShape::Whole,
    }
}

/// `v` without enclosing parentheses and C-style casts (`(char *)p`), which
/// still copy the handle.
fn strip_parens_and_casts(mut v: Node) -> Node {
    v = unwrap_parens(v);
    while v.fkind() == "cast_expression" {
        let Some(inner) = v.child_by_field_name("value") else {
            break;
        };
        v = unwrap_parens(inner);
    }
    v
}

fn extract_member_field_name(node: Node, code: &[u8]) -> Option<String> {
    match node.fkind() {
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

/// PHP `$x = (int) $y;`, `$x = ($a - 1) * $b;`: the assigned value is a
/// number. `+` is left out (array union), as is `.` (concatenation).
fn php_assigns_number(ast: Node, code: &[u8]) -> bool {
    let assign = match ast.fkind() {
        "assignment_expression" => ast,
        "expression_statement" => match ast.named_child(0) {
            Some(c) if c.fkind() == "assignment_expression" => c,
            _ => return false,
        },
        _ => return false,
    };
    // Only a plain variable target: a field or element write is a weak
    // update of its base, so it must keep the taint flowing as before.
    if assign
        .child_by_field_name("left")
        .is_none_or(|l| l.fkind() != "variable_name")
    {
        return false;
    }
    let Some(mut rhs) = assign.child_by_field_name("right") else {
        return false;
    };
    while rhs.fkind() == "parenthesized_expression" {
        match rhs.named_child(0) {
            Some(inner) => rhs = inner,
            None => return false,
        }
    }
    match rhs.fkind() {
        "cast_expression" => rhs
            .child_by_field_name("type")
            .and_then(|t| text_of(t, code))
            .is_some_and(|t| {
                matches!(
                    t.trim().to_ascii_lowercase().as_str(),
                    "int" | "integer" | "float" | "double" | "real" | "bool" | "boolean"
                )
            }),
        "binary_expression" => rhs
            .child_by_field_name("operator")
            .is_some_and(|op| matches!(op.fkind(), "-" | "*" | "/" | "%" | "**")),
        _ => false,
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
                .find(|c| matches!(c.fkind(), "variable_declarator" | "init_declarator"))
                .and_then(|d| {
                    d.child_by_field_name("value")
                        .or_else(|| d.child_by_field_name("initializer"))
                })
        })
        .unwrap_or(ast);
    is_numeric_length_access_expr(target, code)
}

fn is_numeric_length_access_expr(node: Node, code: &[u8]) -> bool {
    match node.fkind() {
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
    let ast_kind = ast.fkind();

    // Check if ast itself is a binary expression
    if is_binary_expr_kind(ast_kind, lang) {
        // Verify it has exactly 2 named children (left, right), no nesting
        let named_count = ast.named_child_count();
        if named_count == 2 {
            // Ensure neither child is itself a binary expression (that would
            // mean the operator is for a compound expression like `a + b * c`)
            let left = ast.named_child(0);
            let right = ast.named_child(1);
            let left_is_bin = left.is_some_and(|n| is_binary_expr_kind(n.fkind(), lang));
            let right_is_bin = right.is_some_and(|n| is_binary_expr_kind(n.fkind(), lang));
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
            if is_binary_expr_kind(child.fkind(), lang) {
                if found.is_some() {
                    return None; // Multiple binary expressions → ambiguous
                }
                // Same check: must have exactly 2 non-binary named children
                if child.named_child_count() == 2 {
                    let l = child.named_child(0);
                    let r = child.named_child(1);
                    let l_bin = l.is_some_and(|n| is_binary_expr_kind(n.fkind(), lang));
                    let r_bin = r.is_some_and(|n| is_binary_expr_kind(n.fkind(), lang));
                    if !l_bin && !r_bin {
                        found = Some(child);
                    }
                }
            } else if wrapper_kinds.contains(&child.fkind()) {
                // Recurse one more level into nested wrappers (e.g.,
                // variable_declaration → variable_declarator → binary_expression)
                let mut inner_cursor = child.walk();
                for grandchild in child.named_children(&mut inner_cursor) {
                    if is_binary_expr_kind(grandchild.fkind(), lang) {
                        if found.is_some() {
                            return None;
                        }
                        if grandchild.named_child_count() == 2 {
                            let l = grandchild.named_child(0);
                            let r = grandchild.named_child(1);
                            let l_bin = l.is_some_and(|n| is_binary_expr_kind(n.fkind(), lang));
                            let r_bin = r.is_some_and(|n| is_binary_expr_kind(n.fkind(), lang));
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

/// Classification text for a for-each loop's iterable expression.
///
/// Subscript / index / slice iterables (`$_GET['x']`, `params[:list]`,
/// `arr[i]`, Go `xs[1:]`) classify on their **base object**: taint sources
/// are keyed on the base name (`$_GET`, `params`), and the trailing index
/// would otherwise break the word-boundary suffix match in `classify`.
/// Non-subscript iterables (method calls, member chains, bare identifiers)
/// use their full text.
fn iterable_label_text(iter: Node, code: &[u8]) -> Option<String> {
    if matches!(
        iter.fkind(),
        "subscript_expression"
            | "subscript"
            | "index_expression"
            | "element_reference"
            | "slice_expression"
    ) {
        let base = iter
            .child_by_field_name("object")
            .or_else(|| iter.child_by_field_name("operand"))
            .or_else(|| iter.child_by_field_name("value"))
            .or_else(|| iter.child(0));
        if let Some(b) = base
            && let Some(t) = text_of(b, code)
        {
            return Some(t);
        }
    }
    text_of(iter, code)
}

/// Build [`HoistedSink`] provenance for `inner_call`, the callback-nested sink
/// whose `Sink` label [`first_callback_sink_call`] found being hoisted onto an
/// outer wrapper node.  Mirrors the gate-classification path used for a node's
/// own `sink_payload_args`: run the gated-sink registry against the inner
/// callee to recover its payload-arg positions (expanding the dynamic
/// `ALL_ARGS_PAYLOAD` sentinel to the inner call's arity) and capture the inner
/// call's per-argument string literals.
fn compute_hoisted_sink(inner_call: Node, lang: &str, code: &[u8]) -> HoistedSink {
    let arg_string_literals = extract_arg_string_literals(inner_call, code);

    let callee_text = inner_call
        .child_by_field_name("function")
        .or_else(|| inner_call.child_by_field_name("method"))
        .or_else(|| inner_call.child_by_field_name("name"))
        .and_then(|f| member_expr_text(f, code).or_else(|| text_of(f, code)))
        .map(|t| t.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .unwrap_or_default();

    let matches = classify_gated_sink_with_presence(
        lang,
        &callee_text,
        |idx| {
            extract_const_string_arg(inner_call, idx, code).or_else(|| {
                if matches!(lang, "c" | "cpp" | "c++" | "php" | "ruby" | "rb") {
                    extract_const_macro_arg(inner_call, idx, code)
                } else {
                    None
                }
            })
        },
        |kw| {
            extract_const_keyword_arg(inner_call, kw, code).or_else(|| {
                if matches!(lang, "javascript" | "typescript") {
                    extract_object_arg_property(inner_call, 1, kw, code)
                } else {
                    None
                }
            })
        },
        |kw| {
            has_keyword_arg(inner_call, kw, code)
                || (matches!(lang, "javascript" | "typescript")
                    && has_object_arg_property(inner_call, 1, kw, code))
        },
        |idx| call_has_arg_at(inner_call, idx),
    );

    let mut payload: Vec<usize> = Vec::new();
    for gm in &matches {
        if gm.payload_args == crate::labels::ALL_ARGS_PAYLOAD {
            let arity = extract_arg_uses(inner_call, code).len();
            for p in 0..arity {
                if !payload.contains(&p) {
                    payload.push(p);
                }
            }
        } else {
            for &p in gm.payload_args {
                if !payload.contains(&p) {
                    payload.push(p);
                }
            }
        }
    }

    HoistedSink {
        payload_args: (!payload.is_empty()).then_some(payload),
        arg_string_literals,
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

    // Branch and loop headers (`if`, elif, `while`, `for`, `loop`, the switch
    // fallback header) are pushed over the whole statement but stand for
    // their condition or iterable only.  `scope` is the subtree every label
    // and call probe below may look at, so a call in the branch or loop body,
    // which is lowered as a node of its own, never labels the header.
    let header = if matches!(kind, StmtKind::If | StmtKind::Loop) {
        control_header_expr(ast, lang)
    } else {
        None
    };
    let scope: Option<Node<'a>> = match header {
        Some(h) => h.node(),
        None => Some(ast),
    };

    // Primary guess (varies by AST kind)
    let mut text = match lookup_node(lang, ast) {
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
                if lookup_node(lang, unwrapped) == Kind::Function {
                    Some(anon_fn_name(unwrapped.start_byte()))
                } else {
                    call_fn_callee_text(n, lang, code)
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

        // everything else – fallback to raw slice.  A for-each header
        // classifies on its iterable; other headers have no text of their
        // own, a call in their condition is classified further down.
        _ => match header {
            Some(HeaderExpr::Iterable(iter)) => iterable_label_text(iter, code).unwrap_or_default(),
            Some(_) => String::new(),
            None => text_of(ast, code).unwrap_or_default(),
        },
    };

    // C++ new/delete: normalize callee to "new"/"delete" for resource pair
    // matching.  Without this, new_expression extracts the type name (e.g.
    // "int") and delete_expression extracts the full expression text.
    // Guarded to C++ only so JS/TS `new_expression` is unaffected.
    if lang == "cpp" {
        if ast.fkind() == "new_expression" {
            text = "new".to_string();
        } else if ast.fkind() == "delete_expression" {
            text = "delete".to_string();
        }
    }

    // Ruby backtick shell execution: the `subshell` AST node has no
    // `function`/`method` field so the CallFn text extraction above yields
    // "".  Stamp a synthetic callee name so the Sink(SHELL_ESCAPE) rule in
    // labels/ruby.rs fires.
    if lang == "ruby" && ast.fkind() == "subshell" {
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
        && ast.fkind() == "for_in_statement"
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
        && ast.fkind() == "for_statement"
        && let Some(right) = ast.child_by_field_name("right")
        && let Some(iter_text) = text_of(right, code)
    {
        text = iter_text;
    }

    // Java `for (T x : iter)`: tree-sitter-java emits `enhanced_for_statement`
    // with the iterable on the `value` field.  Classify against the iterable
    // text so a source-returning call (`req.getCookies()`,
    // `req.getParameterValues(..)`) lights up a Source on the loop node and
    // the loop binding inherits its taint — the same loop-binding-inherits-
    // iterator-taint contract the JS/Python rewrites above provide.  The
    // loop variable itself is recorded as a define by `def_use`'s Kind::For
    // arm (via the `name`/`value` mapping), so the Source-labeled loop node
    // taints the binding directly.
    if lang == "java"
        && ast.fkind() == "enhanced_for_statement"
        && let Some(value) = ast.child_by_field_name("value")
        && let Some(iter_text) = iterable_label_text(value, code)
    {
        text = iter_text;
    }

    // PHP `foreach ($iter as $v)` / `foreach ($iter as $k => $v)`: the
    // iterable is the named child immediately preceding the `as` keyword
    // (only `body` is a named field).  Classify against the iterable text so
    // a superglobal/source iterable (`$_GET[..]`, `$_POST[..]`) taints the
    // loop binding, matching the JS/Python/Java rewrites.
    if lang == "php" && ast.fkind() == "foreach_statement" {
        let mut cursor = ast.walk();
        let kids: Vec<Node> = ast.children(&mut cursor).collect();
        if let Some(as_pos) = kids.iter().position(|c| c.fkind() == "as")
            && let Some(iter_node) = kids[..as_pos].iter().rev().find(|c| c.is_named()).copied()
            && let Some(iter_text) = iterable_label_text(iter_node, code)
        {
            text = iter_text;
        }
    }

    // Ruby `for x in coll`: tree-sitter-ruby's `for` node carries the
    // iterable on the `value` field.  (The idiomatic `coll.each { |x| }`
    // form is a method call with a block and is handled by the call/block
    // machinery, not here.)
    if lang == "ruby"
        && ast.fkind() == "for"
        && let Some(value) = ast.child_by_field_name("value")
        && let Some(iter_text) = iterable_label_text(value, code)
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
    let mut php_test_in_output = false;
    if matches!(
        lookup_node(lang, ast),
        Kind::CallWrapper | Kind::Assignment | Kind::Return
    ) {
        // `echo isset($a) ? $a : ''`: `isset` / `empty` only test a value,
        // so the output construct stays the node's callee.
        let php_output = (lang == "php")
            .then(|| php_output_construct(ast, code))
            .flatten();
        let inner_call = first_call_ident_with_span(ast, lang, code).filter(|(name, _)| {
            let test = php_output.is_some() && matches!(name.as_str(), "isset" | "empty");
            php_test_in_output |= test;
            !test
        });
        if let Some((inner, inner_span)) = inner_call {
            text = inner;
            inner_text_span = Some(inner_span);
        } else if lang == "php"
            && let Some(construct) = php_output_construct(ast, code)
        {
            // `print $x;` and `<?= $x ?>`: the keyword is not the node's first
            // child, so name the construct explicitly.
            text = construct.keyword.to_string();
            inner_text_span = Some(construct.keyword_span);
        } else if matches!(lookup_node(lang, ast), Kind::CallWrapper) {
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

    // `\unlink($p)`: the global-namespace prefix names the same builtin.
    if lang == "php" && text.starts_with('\\') {
        text.remove(0);
    }

    let extra = analysis_rules.map(|r| r.extra_labels.as_slice());
    let mut labels = classify_all(lang, &text, extra);

    // `let v: Box<dyn Plugin> = toml::from_str(&s)?;` picks the concrete type
    // from the document exactly like the turbofish form, but the dyn target
    // sits on the declaration, not in the callee text.
    if lang == "rust"
        && crate::labels::is_polymorphic_decode_head(text.split('(').next().unwrap_or("").trim())
        && !labels.contains(&crate::labels::POLYMORPHIC_DECODE)
        && rust_let_decodes_into_dyn(ast, code)
    {
        labels.push(crate::labels::POLYMORPHIC_DECODE);
    }

    // Java stream accessors are sources only when the stream can carry
    // attacker bytes.  The label belongs to the call `text` came from.
    if lang == "java" && labels.iter().any(|l| matches!(l, DataLabel::Source(_))) {
        let source_call = match inner_text_span {
            Some((start, end)) => ast.descendant_for_byte_range(start, end).filter(|c| {
                c.start_byte() == start && c.end_byte() == end && c.fkind() == "method_invocation"
            }),
            None => find_call_node(ast, lang),
        };
        if source_call.is_some_and(|call| java_stream_source_is_local(call, code)) {
            labels.retain(|l| !matches!(l, DataLabel::Source(_)));
        }
    }

    // A loop over a member read whose prefix is the Source
    // (`for (const id of req.body.ids)`, Python `for x in request.json['a']`):
    // the iterator text ends in a field name that no suffix matcher knows,
    // so classify it by its member path, as a declaration's right-hand side
    // would be.
    if labels.is_empty()
        && ((matches!(lang, "javascript" | "typescript" | "tsx")
            && ast.fkind() == "for_in_statement")
            || (lang == "python" && ast.fkind() == "for_statement"))
        && let Some(right) = ast.child_by_field_name("right")
        && matches!(
            right.fkind(),
            "member_expression" | "subscript_expression" | "attribute" | "subscript"
        )
        && let Some(src @ DataLabel::Source(_)) = first_member_label(right, lang, code, extra)
    {
        labels.push(src);
    }

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
        if let Some(cn) = scope.and_then(|s| find_call_node(s, lang)) {
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
                // A header has no text of its own; name it after the
                // condition call that labelled it.
                if header.is_some() && text.is_empty() && !labels.is_empty() {
                    text = chain_text;
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
    // contains the call AST node) reach `push_node` with `ast.fkind() ==
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
    // Identifiers syntactically contained in a nested inner sink call when
    // `find_classifiable_inner_call` / `find_inner_sink_call` overrides the
    // outer callee.  Restricts the taint sink scan to the inner sink's own
    // sub-expression, excluding sibling positions of the enclosing aggregate.
    let mut sink_reaching_uses: Option<Vec<String>> = None;
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
        && scope
            .and_then(|s| find_call_node(s, lang))
            .and_then(|cn| {
                cn.child_by_field_name("function")
                    .or_else(|| cn.child_by_field_name("method"))
            })
            .and_then(|fc| {
                if matches!(fc.fkind(), "member_expression" | "attribute") {
                    fc.child_by_field_name("property")
                        .or_else(|| fc.child_by_field_name("name"))
                        .and_then(|p| text_of(p, code))
                } else {
                    None
                }
            })
            .is_some_and(|leaf| crate::labels::is_promise_callback_method(lang, &leaf));
    // Surface a classifiable nested call when the outer call carries no
    // SINK label of its own.  Two cases:
    //   (a) the outer call is unclassified (`labels.is_empty()`) — surface
    //       any classifiable inner call (`str(eval(expr))` → `eval`).
    //   (b) the outer call is a non-Sink (Sanitizer / Source) label — surface
    //       the inner call ONLY when it is itself a SINK, so an outer
    //       Sanitizer / Source cannot shadow a dangerous nested sink.
    //       e.g. `JSON.parse(await fsp.readFile(tainted))` (FILE_IO sink
    //       hidden under the JSON_PARSE sanitizer, vite CVE-2026-39365),
    //       `escapeHtml(db.query(tainted))`, `String(execSync(tainted))`.
    //       Additive: the existing Sanitizer / Source label is retained
    //       (a JSON_PARSE / HTML_ESCAPE cap on the parsed *result* is
    //       unrelated to the inner sink's path/query/command argument),
    //       and only fires when no Sink label is present yet.
    // Provenance for a Sink label that came from a call nested inside this
    // node (a wrapper's callback body, or an argument position) rather than
    // the node's own callee.  Consumed by the CFG node's
    // `CallMeta.hoisted_sink`.
    let mut hoisted_sink: Option<Box<HoistedSink>> = None;
    // Go `for _, c := range strings.Split(r.URL.Query().Get("k"), ",")`: the
    // iterable's own text names no source, but a source call nested in it
    // taints the loop binding exactly as it would when bound to a variable
    // first.  Only the iterable is searched, never the loop body.
    if lang == "go"
        && labels.is_empty()
        && matches!(lookup_node(lang, ast), Kind::For)
        && let Some(HeaderExpr::Iterable(iter)) = header
        && let Some((inner_text, label @ DataLabel::Source(_), inner_node)) =
            find_classifiable_inner_call(iter, lang, code, extra)
    {
        labels.push(label);
        text = inner_text;
        inner_callee_span = Some((inner_node.start_byte(), inner_node.end_byte()));
    }
    let outer_has_sink_label = labels.iter().any(|l| matches!(l, DataLabel::Sink(_)));
    if !outer_has_sink_label
        && matches!(
            lookup_node(lang, ast),
            Kind::CallWrapper
                | Kind::Assignment
                | Kind::Return
                | Kind::CallFn
                | Kind::CallMethod
                | Kind::CallMacro
        )
    {
        // `labels.is_empty()`: outer call is unclassified — surface ANY
        // classifiable nested call (`str(eval(x))` → `eval`).
        //
        // outer is a non-Sink label (Sanitizer / Source): surface only a
        // nested SINK, recursing PAST the non-sink outer call.  An outer
        // Sanitizer / Source sanitizes the parsed *result* (an unrelated cap
        // on a downstream value), it cannot neutralise the inner sink's
        // path / query / command argument, so the inner sink must still fire.
        // e.g. `JSON.parse(await fsp.readFile(tainted))` (vite CVE-2026-39365
        // FILE_IO path traversal hidden under the JSON_PARSE sanitizer),
        // `escapeHtml(db.query(tainted))`.  `find_inner_sink_call` skips the
        // non-sink outer match and keeps walking into its arguments.
        //
        // A gated sink (`subprocess.Popen`, `requests.get`) carries no flat
        // label, so it reaches here unclassified.  A sanitizer nested in its
        // arguments cleans only its own result, so it must not take over the
        // callee (the gate below would no longer match, and the sink with
        // it); a nested source or sink still does.  The sink check applies
        // the sanitizer to the operands it wraps through the nested-call
        // tree.
        //
        // The gate lookup only matters when the first inner call found is a
        // sanitizer: when it is a source or sink, the search that skips
        // sanitizers finds the same call first, so the common case pays for
        // one walk and no gate lookup.
        let inner = if labels.is_empty() {
            match find_classifiable_inner_call(ast, lang, code, extra) {
                Some((_, DataLabel::Sanitizer(_), _))
                    if !text.is_empty()
                        && (!crate::labels::classify_gated_sink(
                            lang,
                            &text,
                            |_| None,
                            |_| None,
                            |_| false,
                        )
                        .is_empty()
                            || find_call_node(ast, lang).is_some_and(|cn| {
                                // The call's own arguments select the gate
                                // (`shell=True`), or it is an inline shell
                                // array (`Popen(["sh", "-c", x])`).
                                literals::chain_level_is_gated(lang, &text, cn, code)
                                    || (matches!(
                                        lang,
                                        "javascript" | "js" | "typescript" | "ts" | "python" | "py"
                                    ) && !extract_shell_array_payload_idents(cn, code)
                                        .is_empty())
                            })) =>
                {
                    find_inner_source_or_sink_call(ast, lang, code, extra)
                }
                found => found,
            }
        } else {
            find_inner_sink_call(ast, lang, code, extra)
        };
        // A nested `p.getInputStream()` on a child process is not a source.
        let inner = inner.filter(|(_, label, node)| {
            !(lang == "java"
                && matches!(label, DataLabel::Source(_))
                && java_stream_source_is_local(*node, code))
        });
        if let Some((inner_text, inner_label, inner_node)) = inner {
            let inner_is_sink = matches!(inner_label, DataLabel::Sink(_));
            labels.push(inner_label);
            if !outer_is_promise_callback {
                outer_callee = Some(text.clone());
                text = inner_text;
                inner_callee_span = Some((inner_node.start_byte(), inner_node.end_byte()));
                // JS/TS: a sink call nested in an argument position
                // (`User.findAll({ where: Sequelize.literal(`const`) })`)
                // has payload positions of its own, which the outer call's
                // `sink_payload_args` / `arg_string_literals` do not describe.
                // Record the nested sink calls so the unguarded-sink check can
                // tell a constant payload from a tainted one.  Every sink call
                // the statement names as a member expression is a candidate;
                // all must be constant, so a constant sink cannot vouch for a
                // tainted one beside it.
                if inner_is_sink
                    && matches!(lang, "javascript" | "typescript" | "tsx")
                    && matches!(
                        lookup_node(lang, inner_node),
                        Kind::CallFn | Kind::CallMethod
                    )
                {
                    let mut calls = nested_member_sink_calls(ast, lang, code, extra);
                    if let Some(calls) = calls.as_mut()
                        && !calls.iter().any(|c| c.id() == inner_node.id())
                    {
                        calls.push(inner_node);
                    }
                    // A sink member expression that is not a call callee has no
                    // call provenance; leave the node unproven then.
                    if let Some(mut calls) = calls {
                        calls.sort_by_key(|c| c.start_byte());
                        let mut all: Vec<HoistedSink> = calls
                            .into_iter()
                            .map(|c| compute_hoisted_sink(c, lang, code))
                            .collect();
                        // Recorded only when every one is constant: a node with
                        // a non-constant sink keeps the checks it had before.
                        if all.iter().all(HoistedSink::is_constant) {
                            hoisted_sink = Some(Box::new(all.swap_remove(0)));
                        }
                    }
                }
                // Inner-nested-sink argument attribution.  The Sink label was
                // contributed by a call nested inside a larger, non-sink outer
                // expression (`Ok(Reader { meta: <tainted>, h:
                // File::open(const) })`, `str(eval(x))`).  Record the
                // identifiers that syntactically appear *inside* that inner
                // sink call so the taint sink scan can exclude values that
                // occupy a DIFFERENT sub-position of the enclosing aggregate
                // (a sibling struct field / tuple element), which are NOT the
                // sink's payload.  Only meaningful for sink overrides — a
                // Source/Sanitizer override taints the wrapper's *result*, a
                // separate channel handled elsewhere.
                if inner_is_sink {
                    let mut idents = Vec::new();
                    let mut paths = Vec::new();
                    collect_idents_with_paths(inner_node, code, &mut idents, &mut paths);
                    paths.extend(idents);
                    if !paths.is_empty() {
                        sink_reaching_uses = Some(paths);
                    }
                }
            }
        }
    }

    // For assignments like `element.innerHTML = value`, the inner-call heuristic
    // above may have overridden `text` with a call on the RHS (e.g. getElementById).
    // If that didn't produce a label, check the LHS property name, it may be a
    // sink like `innerHTML`.
    //
    // This covers both direct `Kind::Assignment` nodes and `Kind::CallWrapper`
    // nodes (expression_statement) that wrap an assignment.
    //
    // JS/TS: a Source label the RHS call contributed
    // (`location.href = location.hash.substring(1)`, where the string method
    // on a source classifies as one) gives way to a sink target.  The node's
    // sink check reads the pre-emitted RHS member source
    // (`pre_emit_sink_assignment_sources`) instead; a node that kept the
    // Source label would lower to a source definition with no sink check.
    // A Sanitizer or Sink from the RHS still wins.
    let rhs_source_only = matches!(lang, "javascript" | "typescript" | "tsx")
        && !labels.is_empty()
        && labels.iter().all(|l| matches!(l, DataLabel::Source(_)));
    let unlabelled_before_target_check = labels.is_empty() || rhs_source_only;
    if labels.is_empty() || rhs_source_only {
        let assign_node = if matches!(lookup_node(lang, ast), Kind::Assignment) {
            Some(ast)
        } else if matches!(lookup_node(lang, ast), Kind::CallWrapper) {
            // Walk children to find a nested assignment_expression
            let mut cursor = ast.walk();
            ast.children(&mut cursor)
                .find(|c| matches!(lookup_node(lang, c), Kind::Assignment))
        } else {
            None
        };

        if let Some(assign) = assign_node
            && let Some(lhs) = assign.child_by_field_name("left")
            && let Some(l) = classify_assignment_lhs(lhs, lang, code, extra)
            // An assignment target is written, not read: only a Sink label
            // (`el.innerHTML = x`) is meaningful.  A Source or Sanitizer
            // label on the target (`req.path = '/x'`, `req.headers[k] = v`)
            // would turn a write into a read of attacker data.
            && matches!(l, DataLabel::Sink(_))
            && !is_koa_json_body_assignment(assign, lhs, lang, code, &l)
        {
            if rhs_source_only {
                labels.clear();
            }
            labels.push(l);
        }
    }
    // The label now belongs to the assignment target, not to the call `text`
    // names, so that call cannot anchor the node's call nesting.
    let labelled_by_assign_target = unlabelled_before_target_check && !labels.is_empty();

    // Set when the hoist block below rewrites `text` to a member expression
    // found inside the node rather than the node's own callee.
    let mut text_from_member_label = false;

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
    //
    // A bare `return <member source>` (`return req.query.q`,
    // `return os.environ["X"]`, `return $_GET['id']`) is a read of that
    // source too, so a one-line getter helper carries source caps in its
    // summary.  Only a Source label attaches to a return, since a return is
    // never a sink assignment.  A return with a call is already split into a
    // Call node plus a Return node (whose argument sources are pre-emitted),
    // and a returned closure returns the closure, not what its body reads.
    let is_bare_return = lookup_node(lang, ast) == Kind::Return
        && !has_call_descendant(ast, lang)
        && !has_function_descendant(ast, lang);
    if labels.is_empty()
        && (is_bare_return
            || (matches!(lookup_node(lang, ast), Kind::CallWrapper | Kind::Assignment)
                && !rhs_is_function_literal(ast, lang)))
        && let Some(found) = first_member_label(ast, lang, code, extra)
        && (!is_bare_return || matches!(found, DataLabel::Source(_)))
        && !is_koa_json_body_node(ast, lang, code, &found)
    {
        let hoisted_is_sink = matches!(found, DataLabel::Sink(_));
        let hoisted_is_source = matches!(found, DataLabel::Source(_));
        labels.push(found);
        // When the hoisted label is a Sink contributed from inside a
        // callback-argument function literal (the `sequelize.transaction(async
        // (t) => { sequelize.query(`…`, opts) })` idiom), record the INNER sink
        // call's own payload-arg positions + argument string literals.  The
        // wrapper's own arguments are the callback, not the payload, so
        // `sink_payload_args_syntactic_const` must check the inner call to
        // decide whether the phantom `cfg-unguarded-sink` on the wrapper is a
        // false positive (constant inner payload) or a real flow (tainted).
        //
        // `first_callback_sink_call` descends argument positions only, never a
        // call's callee/receiver side, so provenance can only come from a
        // callback this node actually passes.  Without that restriction a
        // chained call picked up a sink nested in the RECEIVER's callback:
        // `http.get(target, cb).on('error', cb2)` recorded `res.send('ok')`
        // from inside `http.get`'s callback as provenance for the `.on` node,
        // and that unrelated `'ok'` literal then masqueraded as a constant
        // payload and suppressed a real SSRF finding.
        if hoisted_is_sink && let Some(inner) = first_callback_sink_call(ast, lang, code, extra) {
            hoisted_sink = Some(Box::new(compute_hoisted_sink(inner, lang, code)));
        }
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
            if let Some(member_text) = first_member_text(ast, code, hoisted_is_source) {
                if outer_callee.is_none() && text != member_text {
                    outer_callee = Some(text.clone());
                }
                text = member_text;
                text_from_member_label = true;
            }
        }
    }

    // JS/TS: a sink call nested in the value an assignment or declaration
    // binds (`where = { [Op.and]: [Sequelize.literal(`const`)] }`) names the
    // node's callee but is not the statement's own call, so no payload
    // positions describe it.  Record every nested sink call; the unguarded-sink
    // check then proves the node constant only when all of them are.
    if hoisted_sink.is_none()
        && matches!(lang, "javascript" | "typescript" | "tsx")
        && matches!(lookup_node(lang, ast), Kind::Assignment | Kind::CallWrapper)
        && labels.iter().any(|l| matches!(l, DataLabel::Sink(_)))
        && scope.and_then(|s| find_call_node(s, lang)).is_none()
        && let Some(calls) = nested_member_sink_calls(ast, lang, code, extra)
        && !calls.is_empty()
    {
        let mut all: Vec<HoistedSink> = calls
            .into_iter()
            .map(|c| compute_hoisted_sink(c, lang, code))
            .collect();
        if all.iter().all(HoistedSink::is_constant) {
            hoisted_sink = Some(Box::new(all.swap_remove(0)));
        }
    }

    // Set when `text` below is the callee of a call in a condition header.
    let mut cond_call_text = false;
    // Conditions can contain source/sink calls whose argument side effects are
    // load-bearing for taint, e.g. C `if (!fgets(buf, n, stdin)) return;`.
    // Classify the condition call so output-parameter sources still lower as
    // SSA calls while the CFG node keeps its branch shape.  Covers every
    // condition header (`if`, elif, `while`, `do`, a C-style `for`); the
    // header takes the condition call's callee as its text either way, so
    // the gated-sink pass below matches against that call.
    if labels.is_empty()
        && let Some(HeaderExpr::Condition(cond)) = header
        && let Some((ident, ident_span)) = call_ident_at_or_under(cond, lang, code)
    {
        if let Some(l) = classify(lang, &ident, extra) {
            labels.push(l);
        }
        text = ident;
        cond_call_text = true;
        if inner_text_span.is_none() {
            inner_text_span = Some(ident_span);
        }
    }

    // For `if let` / `while let` patterns: try to classify the value expression
    // in the let-condition as a source/sink.  E.g. `if let Ok(cmd) = env::var("CMD")`
    // should recognise `env::var` as a taint source and label this node accordingly.
    if labels.is_empty()
        && matches!(lookup_node(lang, ast), Kind::If | Kind::While)
        && let Some(cond) = ast.child_by_field_name("condition")
        && cond.fkind() == "let_condition"
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
    let mut call_ast = scope.and_then(|s| find_call_node(s, lang));
    // C / C++ `if ((x = getenv("V")) == NULL)`: the assigned call sits deeper
    // than the generic probe looks, and it is the call the header evaluates.
    if call_ast.is_none()
        && matches!(lang, "c" | "cpp")
        && header.is_some()
        && let Some(cond) = scope
    {
        call_ast = literals::condition_assigned_call(cond, lang);
    }

    // Go `p = "/" + strings.Trim(q, "/")`: the call is the right operand of a
    // concatenation, one level deeper than `find_call_node` looks.  It is
    // still the node's only call, so its arguments and literals describe the
    // node the way they do for `p = strings.Trim(q, "/")`.
    let go_concat_operand = if lang == "go" && call_ast.is_none() {
        scope.and_then(|s| go_literal_plus_operand(s, code))
    } else {
        None
    };
    if let Some((_, operand)) = go_concat_operand
        && operand.fkind() == "call_expression"
    {
        call_ast = Some(operand);
    }

    // Rust `conn.execute(sql, params![v]).unwrap()`: `.unwrap()` / `.expect(..)`
    // only unwrap the result, so the arguments that matter for gate payload
    // positions belong to the call underneath.  Without this the outermost
    // call carries no arguments and a typed-receiver SQL sink scans every use,
    // including the bound parameters.
    //
    // The receiver of the peeled call is not examined by the literal-argument
    // check, so a rebind never counts as "all arguments literal".
    let mut rust_call_rebound = false;
    if lang == "rust"
        && let Some(outer) = call_ast
        && let Some(inner) = peel_rust_result_unwrap(outer, code)
    {
        call_ast = Some(inner);
        rust_call_rebound = true;
    }

    // Rust `sqlx::query(sql).bind(v).fetch_all(pool)` takes the same route: the
    // head classifies as the SQL sink and the outermost call is `.fetch_all`.
    //
    // Python `conn.execute(sql, params).fetchall()` classifies on its head
    // (`conn.execute`, the text before the first `(`), so the node already has
    // its Sink label while the outermost call is the zero-arg `.fetchall()`.
    // The gate's payload positions and the literal-SQL check refer to the sink
    // call's arguments, so rebind to that call the way the block below does
    // for an unclassified outer call.
    if matches!(lang, "python" | "rust")
        && text.contains('(')
        && labels.iter().any(|l| matches!(l, DataLabel::Sink(_)))
        && let Some(outer) = call_ast
        && let Some((inner, inner_callee_text)) = find_chained_gated_sink_call(outer, lang, code)
        && inner.id() != outer.id()
        && {
            let inner_gates =
                classify_gated_sink(lang, &inner_callee_text, |_| None, |_| None, |_| false);
            // Rust: the outer sink keeps its own arguments unless the inner
            // gate is the same sink class (`sqlx::query(sql).bind(v)`).  A
            // different-cap inner gate (`File::create(p).unwrap().write_all(..)`)
            // must not displace the outer sink's argument scan.
            !inner_gates.is_empty()
                && (lang != "rust"
                    || inner_gates.iter().any(|g| match g.label {
                        DataLabel::Sink(c) => labels.iter().any(|l| match l {
                            DataLabel::Sink(oc) => !(*oc & c).is_empty(),
                            _ => false,
                        }),
                        _ => false,
                    }))
        }
    {
        call_ast = Some(inner);
        rust_call_rebound |= lang == "rust";
        outer_callee = Some(text.clone());
        text = inner_callee_text;
        inner_callee_span = Some((inner.start_byte(), inner.end_byte()));
    }

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
    //
    // A Source the node picked up only from a member read inside the call
    // (`.where(req.query.name).getMany()`, hoisted by the block above) does
    // not make the outer call a classified callee: the chain is rebound and
    // the hoisted Source stays on the node.
    let only_hoisted_source = text_from_member_label
        && !labels.is_empty()
        && labels.iter().all(|l| matches!(l, DataLabel::Source(_)));
    if (labels.is_empty() || only_hoisted_source)
        && let Some(outer) = call_ast
        && let Some((inner, inner_callee_text)) = find_chained_gated_sink_call(outer, lang, code)
            .or_else(|| find_chained_inner_call(outer, lang, code))
        && literals::chain_level_is_gated(lang, &inner_callee_text, inner, code)
    {
        call_ast = Some(inner);
        if !only_hoisted_source {
            outer_callee = Some(text.clone());
        }
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
        let gate_call = call_ast.or_else(|| scope.and_then(|s| find_call_node_deep(s, lang, 4)));
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
            // The same holds for a Sink that `first_member_label` found on a
            // function *reference* passed as an argument
            // (`apply(child_process.exec, cmd)`): the gate of the referenced
            // function describes its own parameters, not this call's.
            // Whitespace is stripped to mirror `find_chained_inner_call`
            // so multi-line chains (`http\n  .get(...)`) still match flat
            // gate matchers like `http.get`.
            let function_field_text: Option<String> = cn
                .child_by_field_name("function")
                .or_else(|| cn.child_by_field_name("method"))
                .or_else(|| cn.child_by_field_name("name"))
                .and_then(|f| call_fn_callee_text(f, lang, code))
                .map(|t| t.chars().filter(|c| !c.is_whitespace()).collect::<String>());
            // PHP `$obj->method()` keeps its receiver in the `object` field,
            // so the `name` field alone is the bare method name, which would
            // match an exact-name gate (`=unlink`) meant for the builtin.
            let function_field_text = if lang == "php"
                && lookup_node(lang, cn) == Kind::CallMethod
                && let Some((qualified, _)) = call_node_ident_with_span(cn, lang, code)
            {
                Some(
                    qualified
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect::<String>(),
                )
            } else {
                function_field_text
            };
            let has_source_label = labels
                .iter()
                .any(|l| matches!(l, crate::labels::DataLabel::Source(_)));
            let member_ref_sink = text_from_member_label && hoisted_sink.is_none();
            // Clippy flags one branch's clone as redundant because it cannot
            // see that `text` is read after this `let` (further down in this
            // function); silence the false positive without restructuring.
            #[allow(clippy::redundant_clone)]
            let gate_callee_text = if let Some(ff) = function_field_text.as_deref()
                && (has_source_label || member_ref_sink)
                && ff != text.as_str()
            {
                ff.to_string()
            } else if call_ast.is_some() && !text.is_empty() {
                text.clone()
            } else {
                function_field_text.unwrap_or_else(|| text.clone())
            };
            let mut matches = classify_gated_sink_with_presence(
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
                |idx| call_has_arg_at(cn, idx),
            );

            if lang == "java" && !matches.is_empty() {
                java_veto_non_reflective_lookup(ast, &gate_callee_text, code, &mut matches);
            }

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
                    // A string-evaluating timer (`setTimeout(code, ms)`) is a
                    // sink only when arg 0 is a string by construction.  Its
                    // usual argument is a callback (a function literal, a
                    // named function, a Promise `resolve`), which compiles
                    // nothing; the callback body is analysed on its own.
                    if matches!(lang, "javascript" | "typescript" | "tsx")
                        && matches!(gm.label, DataLabel::Sink(c) if c.contains(Cap::CODE_EXEC))
                        && crate::labels::javascript::STRING_EVALUATING_TIMERS
                            .contains(&gate_callee_text.rsplit('.').next().unwrap_or(""))
                        && !js_arg_is_string_valued(cn, 0, lang, code, extra)
                    {
                        continue;
                    }
                    // A query-builder condition given as an object, a
                    // `Brackets` group or a callback is built from bound
                    // parameters, not spliced in as SQL text.
                    if matches!(lang, "javascript" | "typescript" | "tsx")
                        && matches!(gm.label, DataLabel::Sink(c) if c.contains(Cap::SQL_QUERY))
                        && gate_callee_text
                            .strip_prefix("QueryBuilder.")
                            .is_some_and(|m| {
                                crate::labels::javascript::QUERY_BUILDER_SQL_TEXT_METHODS
                                    .contains(&m)
                                    && js_arg_is_structured_condition(cn, 0, m, code)
                            })
                    {
                        continue;
                    }
                    // A shallow `Object.assign(target, src)` pollutes a shared
                    // prototype only when `target` is one.
                    if matches!(lang, "javascript" | "typescript" | "tsx")
                        && matches!(gm.label, DataLabel::Sink(c) if c.contains(Cap::PROTOTYPE_POLLUTION))
                        && crate::labels::javascript::SHALLOW_ASSIGN_MERGES
                            .contains(&gate_callee_text.as_str())
                        && !js_arg_is_prototype_object(cn, 0, code)
                    {
                        continue;
                    }
                    // Python lowers keyword arguments into the use group that
                    // follows the positional ones, so a payload position the
                    // call does not pass would read the keywords instead.  A
                    // gate that names its keyword destinations (`url=`) has
                    // its payload in those or in a passed position; with
                    // neither, the call gives this gate no payload.
                    let py_arity = if lang == "python" && !gm.object_destination_fields.is_empty() {
                        python_positional_arity(cn)
                    } else {
                        None
                    };
                    if let Some(arity) = py_arity
                        && gm.payload_args != crate::labels::ALL_ARGS_PAYLOAD
                        && gm.payload_args.iter().all(|&p| p >= arity)
                        && extract_destination_kwarg_pairs(cn, gm.object_destination_fields, code)
                            .is_empty()
                    {
                        continue;
                    }
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

                    // Go database calls that lead with a `context.Context`
                    // (`db.Exec(ctx, query, args...)`) carry the SQL one
                    // position later than the context-free forms the gate
                    // describes.
                    if lang == "go"
                        && payload_vec.as_slice() == [0]
                        && matches!(gm.label, DataLabel::Sink(c) if c.contains(Cap::SQL_QUERY))
                        && gm.object_destination_fields.is_empty()
                        && go_leading_arg_is_context(cn, code)
                    {
                        payload_vec = vec![1];
                    }

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
                                // An inline member Source in a destination
                                // field is bound to the argument's synthetic
                                // source; keep a placeholder that
                                // `apply_arg_source_bindings` resolves.
                                if let Some(field) = destination_field_reading_source(
                                    cn,
                                    pos,
                                    gm.object_destination_fields,
                                    lang,
                                    code,
                                    extra,
                                ) {
                                    all_pairs.push((field, arg_source_placeholder(pos)));
                                }
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
                        if let Some(arity) = py_arity {
                            payload_vec.retain(|&p| p < arity);
                        }
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

    // `child_process.spawn(bin, argv, { shell: true })` and the other
    // argv-taking forms: the gate above restricted the sink to the binary,
    // but an enabled `shell` option makes the argv array part of the shell
    // command.
    if let Some(cn) = call_ast {
        let extra_payload = js_shell_option_payload(lang, &text, &labels, cn, code);
        if !extra_payload.is_empty()
            && let Some(payload) = sink_payload_args.as_mut()
        {
            for p in extra_payload {
                if !payload.contains(&p) {
                    payload.push(p);
                }
                for f in gate_filters
                    .iter_mut()
                    .filter(|f| f.label_caps.contains(Cap::SHELL_ESCAPE))
                {
                    if !f.payload_args.contains(&p) {
                        f.payload_args.push(p);
                    }
                }
            }
        }
    }

    // A JS/TS payload position the call does not pass carries no payload.
    // Without this trim, a zero-arg `res.json()` / `res.status(code).json()`
    // is checked against the SSA lowering's fallback argument group, which
    // lumps the receiver and the chain links' own arguments together, and
    // the structural pass reports the call as an unguarded sink.
    // Only applies when the classified callee is the call's own function:
    // not when `text` holds a nested call (`http.request(url, cb).end()`,
    // where the gate matched the chain head, whose arguments live in that
    // fallback group), and not when an inner call's callee replaced the
    // node's own (`require('child_process').execSync(cmd).toString()`, where
    // `call_ast` is still the outer zero-arg call).  Also skipped when a
    // spread argument hides the real arity.
    if matches!(lang, "javascript" | "typescript" | "tsx")
        && !text.contains('(')
        && outer_callee.is_none()
        && let Some(cn) = call_ast.or_else(|| find_call_node_deep(ast, lang, 4))
        && let Some(arity) = js_positional_arity(cn)
        && let Some(payload) = sink_payload_args.as_mut()
    {
        payload.retain(|&p| p < arity);
        if payload.is_empty() {
            // Every payload position is absent, so the call writes nothing
            // a sink could receive and is not a sink at this site.
            labels.retain(|l| !matches!(l, DataLabel::Sink(_)));
            sink_payload_args = None;
            destination_uses = None;
            gate_filters.clear();
        } else {
            for f in &mut gate_filters {
                f.payload_args.retain(|&p| p < arity);
            }
        }
    }

    // Tagged SQL templates bind their substitutions as parameters; see
    // `apply_js_sql_template_params`.
    if matches!(lang, "javascript" | "typescript" | "tsx")
        && let Some(cn) = call_ast.or_else(|| find_call_node_deep(ast, lang, 4))
    {
        apply_js_sql_template_params(
            cn,
            code,
            &mut SinkSlots {
                labels: &mut labels,
                payload_args: &mut sink_payload_args,
                gate_filters: &mut gate_filters,
                destination_uses: &mut destination_uses,
                reaching_uses: &mut sink_reaching_uses,
            },
        );
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
    //
    // Python reaches the same shape through `from subprocess import Popen` /
    // `Popen(["bash", "-c", f"... {x}"])` (a `list` literal, f-string payload).
    // When the call is the receiver of a method chain whose outer call is not
    // itself classified (`Popen([...]).wait()`), the chain's inner call is
    // the one that holds the array, so it takes over like in the gated-sink
    // chain rebinding above.
    if matches!(lang, "python" | "py")
        && labels.is_empty()
        && let Some(outer) = call_ast
        && let Some(inner) = literals::chain_receiver_calls(outer, lang)
            .into_iter()
            .find(|c| !extract_shell_array_payload_idents(*c, code).is_empty())
        && let Some(callee_text) = inner
            .child_by_field_name("function")
            .and_then(|f| call_fn_callee_text(f, lang, code))
    {
        call_ast = Some(inner);
        outer_callee = Some(text.clone());
        text = callee_text.chars().filter(|c| !c.is_whitespace()).collect();
        inner_callee_span = Some((inner.start_byte(), inner.end_byte()));
    }
    if matches!(
        lang,
        "javascript" | "js" | "typescript" | "ts" | "python" | "py"
    ) {
        if let Some(cn) = call_ast.or_else(|| scope.and_then(|s| find_call_node_deep(s, lang, 4))) {
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
            if cn.fkind() == "call_expression" || cn.fkind() == "method_call_expression" {
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
            if cn.fkind() == "call_expression" {
                if let Some(caps) = detect_go_replace_call_sanitizer(cn, code) {
                    labels.push(DataLabel::Sanitizer(caps));
                }
            }
        }
    }

    // Go `fmt.Fprint*` / `io.WriteString` into `os.Stderr` / `os.Stdout`
    // or into a formal declared as a byte writer that is not a response
    // (`out io.Writer`, `buf *bytes.Buffer`) is a log, stream or buffer
    // write, not response rendering, so the call is not an XSS sink for any
    // consumer (taint, `cfg-unguarded-sink`, `cfg-error-fallthrough`).  The
    // SSA writer gate sees locals through type facts, but a top-level body
    // is lowered without its formals, so a formal writer has no SSA value
    // there.
    if lang == "go"
        && labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::HTML_ESCAPE)))
        && crate::ssa::type_facts::is_go_writer_sink_callee(&text)
        && call_ast.is_some_and(|cn| go_writer_arg_is_non_response(cn, code))
    {
        for label in labels.iter_mut() {
            if let DataLabel::Sink(c) = label {
                *c &= !Cap::HTML_ESCAPE;
            }
        }
        labels.retain(|l| !matches!(l, DataLabel::Sink(c) if c.is_empty()));
    }

    // Express `res.sendFile(p, { root })` / `res.download(p, { root })`: the
    // `send` module resolves `p` under `root` and rejects any path that
    // climbs out of it, so the call is confined to the root directory and is
    // not a file-read sink for `p`.
    if matches!(lang, "javascript" | "typescript" | "tsx")
        && labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::FILE_IO)))
        && (text.ends_with("res.sendFile")
            || text.ends_with("res.download")
            || text.ends_with("res.sendfile"))
        && let Some(cn) = call_ast
        && literals::object_arg_sets_property_without_spread(cn, 1, "root", code)
        && literals::extract_object_arg_property(cn, 1, "root", code).is_some_and(|v| {
            let t = v.trim_matches(|c| c == '"' || c == '\'' || c == '`');
            v.starts_with(['"', '\'', '`'])
                && v.len() >= 2
                && !t.is_empty()
                && !t.contains("${")
                && !t.trim_matches('/').trim_matches('.').is_empty()
        })
    {
        for label in labels.iter_mut() {
            if let DataLabel::Sink(c) = label {
                *c &= !Cap::FILE_IO;
            }
        }
        labels.retain(|l| !matches!(l, DataLabel::Sink(c) if c.is_empty()));
        if !labels.iter().any(|l| matches!(l, DataLabel::Sink(_))) {
            sink_payload_args = None;
            destination_uses = None;
            gate_filters.clear();
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
            lookup_node(lang, ast),
            Kind::CallWrapper | Kind::Assignment | Kind::Return
        )
        && !labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::HTML_ESCAPE)))
        && jsx_text_content_interp_present(ast, lang)
    {
        labels.push(DataLabel::Sanitizer(Cap::HTML_ESCAPE));
    }

    // Python call shapes the flat sink labels cannot tell apart from the
    // dangerous ones: `make_response(render_template(..))`, a JSON
    // `HttpResponse`, `yaml.load(f, Loader=yaml.SafeLoader)`.
    if lang == "python"
        && let Some(cn) = call_ast
        && let Some(san) =
            python_shapes::safe_shape_sanitizer(&text, cn, code, extra, labels.as_slice())
    {
        labels.push(san);
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
        if scope.is_some_and(|s| ruby_statement_ar_queries_safe(s, code, extra)) {
            labels.push(DataLabel::Sanitizer(Cap::SQL_QUERY));
        }
    }

    // Ruby `system(prog, arg, ...)` / `exec(prog, arg, ...)` with two or more
    // command words and a fixed non-shell program is the argv form: Ruby
    // execs the program directly and never starts a shell, so metacharacters
    // in any word are inert.  The single-string form goes through `/bin/sh`,
    // and a dynamic or shell/interpreter program still runs tainted text as
    // code (see `kernel_exec_is_argv_form`).  The same-node
    // `Sanitizer` follows the AR-query precedent above.
    if (lang == "ruby" || lang == "rb")
        && matches!(text.as_str(), "system" | "exec")
        && labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SHELL_ESCAPE)))
        && !labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::SHELL_ESCAPE)))
        && call_ast.is_some_and(|cn| crate::labels::ruby::kernel_exec_is_argv_form(cn, code))
    {
        labels.push(DataLabel::Sanitizer(Cap::SHELL_ESCAPE));
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
    // `*.query(...)` / `*.execute(...)` whose result has at least one chained
    // method call appended whose name is in the ORM-accessor whitelist AND
    // whose arg 0 is a model-UID *reference* (string literal, const / variable
    // identifier, or member access — see `js_orm_query_arg0_is_uid_ref`).  The
    // trailing ORM method (`findMany` / `findOne` / …) is the discriminator: a
    // raw driver's `query(sql)` returns a Promise that cannot chain those
    // methods, so the chain shape only arises on ORM query builders.  If both
    // hold, synthesise a same-node `Sanitizer(SQL_QUERY)` mirroring the Java
    // JPA fix.  Because `dominates()` is reflexive, the same-node sanitizer
    // also suppresses the parallel structural `cfg-unguarded-sink` finding.
    // Bare `connection.query("SELECT ...")` (no chained ORM method) and
    // `db.query(`UPDATE ... ${name}`)` (interpolated arg 0) leave the sink in
    // place, both are genuine SQLi shapes.
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
            // Strapi Query Engine relation loader: `db.query(uid).load(entity,
            // populate)` returns the populated relation, parameterised like the
            // other accessors.
            "load",
        ];
        // Fall back to a deeper walk (up to 4 levels) for await/return-
        // wrapped calls (e.g. `const x = await db.query(...).findOne(...)` ,
        // call sits at depth 3 inside lexical_declaration > variable_declarator
        // > await_expression > call_expression).
        // Locate the ORM-accessor call `<recv>.query(UID).<orm_method>(...)`
        // robustly.  Real strapi code wraps the chain in forms that defeat the
        // shallow `call_ast` / fixed-depth `find_call_node_deep` lookup:
        //   * `const x = (await db.query(uid).findMany(...))` — the
        //     `(await ...)` wrapper pushes the call past the depth budget, so
        //     both lookups return `None`.
        //   * `return (await db.query(uid).count(...)) > 0` — a binary wrapper.
        //   * `Promise.all([ db.query(model).findOne(...) ])` — `find_call_node`
        //     returns the *outer* `Promise.all` call, whose spine has no
        //     `.query`, so the ORM chain is invisible.
        // A bounded subtree DFS for the specific call whose receiver spine holds
        // an inner `query`/`execute` (via `js_chain_outer_method_for_inner`)
        // finds the right node regardless of wrapping; fall back to the prior
        // lookups only if the DFS finds nothing.
        let mut orm_dfs_budget: u32 = 96;
        let chain_call = scope
            .and_then(|s| find_orm_query_chain_call(s, QUERY_TARGETS, code, &mut orm_dfs_budget))
            .or(call_ast)
            .or_else(|| scope.and_then(|s| find_call_node_deep(s, lang, 4)));
        if let Some(call_node) = chain_call {
            // Outer method must be in the ORM whitelist *and* the chain must
            // have a deeper inner call to a `query`/`execute` whose arg 0 is
            // a model-UID reference.  Both checks gate the synthesis.
            let outer_method = js_chain_outer_method_for_inner(call_node, QUERY_TARGETS, code);
            let outer_is_orm = outer_method
                .as_deref()
                .is_some_and(|m| ORM_CHAIN_METHODS.contains(&m));
            if outer_is_orm
                && let Some((arg0_kind, has_interp)) =
                    js_chain_arg0_kind_for_method(call_node, QUERY_TARGETS, code)
                && !has_interp
                && js_orm_query_arg0_is_uid_ref(arg0_kind.as_str())
            {
                labels.push(DataLabel::Sanitizer(Cap::SQL_QUERY));
            }
        }
    }

    let span = (ast.start_byte(), ast.end_byte());

    /* ── 3.  GRAPH INSERTION + DEBUG ──────────────────────────────────── */

    let (defines, mut uses, extra_defines, array_pattern_indices, rhs_array_elements) =
        def_use(ast, lang, code, extra);
    // `echo isset($a) ? $b : ''`: the `isset` test is not output, so its
    // operands are not uses of the echo.
    if php_test_in_output && let Some(construct) = php_output_construct(ast, code) {
        uses.clear();
        php_output_value_uses(construct.operand, code, &mut uses);
    }
    let rhs_object_literal = match defines.as_deref() {
        Some(name) if extra_defines.is_empty() => collect_rhs_object_literal(ast, lang, code, name),
        _ => None,
    };

    // `x += y` / `x ||= y`: the right-hand side is an operand, not the
    // value of the target, so facts derived from the RHS alone (literal
    // text, template prefix, member-field type, `.length` Int) do not
    // describe the result.
    let rmw = rmw_statement(ast, lang);

    // `$n = (int) $_GET['n']`: the stored value is a number, so a source read
    // on the right-hand side does not label the node as a source.
    let yields_number = lang == "php" && rmw.is_none() && php_assigns_number(ast, code);
    if yields_number {
        labels.retain(|l| !matches!(l, DataLabel::Source(_)));
    }

    // Capture constant text for SSA constant propagation: when this node
    // defines a variable from a syntactic literal (no identifier uses),
    // extract the raw literal text from the AST.  Also capture the
    // argument of a const-return (`return []`) so the SSA const-return
    // synthesis can emit `Const(Some(text))` instead of `Const(None)`,
    // surfacing the literal text to downstream container-literal
    // detection.
    let const_text = if rmw.is_some() {
        None
    } else if (defines.is_some() && uses.is_empty())
        || (kind == StmtKind::Return && uses.is_empty())
    {
        extract_literal_rhs(ast, lang, code)
    } else {
        None
    };

    let const_collection = rmw.is_none()
        && defines.is_some()
        && uses.is_empty()
        && literal_scalar_collection_rhs(ast, lang, code);

    // C / C++ `if (!realpath(dir, out))`: an unlabelled call in a branch or
    // loop condition still writes its output arguments.  Keep it as the
    // node's callee when it has an arg-to-arg propagation rule so the buffer
    // it fills carries the input's taint, as the same call in statement
    // position does.
    let mut header_call_propagates = false;
    if labels.is_empty()
        && header.is_some()
        && matches!(lang, "c" | "cpp")
        && let Some(cn) = call_ast
        && let Some((ident, ident_span)) = call_ident_at_or_under(cn, lang, code)
        && crate::labels::arg_propagation(lang, &ident).is_some()
    {
        text = ident;
        inner_text_span = Some(ident_span);
        header_call_propagates = true;
    }

    let mut callee = if kind == StmtKind::Call || !labels.is_empty() || header_call_propagates {
        Some(text.clone())
    } else {
        None
    };
    // C / C++ `cmp(a, b)` where `cmp` is a function-pointer variable or
    // parameter of the enclosing function.  The name stands for whatever the
    // pointer holds, so it must not resolve to an unrelated function that
    // happens to share the name in this or another file.
    if labels.is_empty()
        && matches!(lang, "c" | "cpp")
        && let Some(c) = callee.as_deref()
        && let Some(cn) = call_ast
        && helpers::c_callee_is_local_pointer(cn, c, code)
    {
        callee = Some(format!("(*{c})"));
    }

    // Call nesting for statement-level nodes that lower to an SSA `Call`.
    // The anchor is the call `text` was taken from: the classified inner
    // call, the first call of a wrapper statement, or the node's own call.
    // It must still name that call (a member-source rewrite of `text` or a
    // label taken from the assignment target leaves no anchor).
    let nested_calls = if callee.is_some()
        && matches!(
            lookup_node(lang, ast),
            Kind::CallWrapper
                | Kind::Assignment
                | Kind::Return
                | Kind::Throw
                | Kind::CallFn
                | Kind::CallMethod
        ) {
        let anchor_span = inner_callee_span.or(inner_text_span).or_else(|| {
            if matches!(lookup_node(lang, ast), Kind::CallFn | Kind::CallMethod) {
                Some((ast.start_byte(), ast.end_byte()))
            } else {
                call_ast.map(|c| (c.start_byte(), c.end_byte()))
            }
        });
        let anchor = if labelled_by_assign_target {
            None
        } else {
            anchor_span.map(|s| (s, text.as_str()))
        };
        nested_calls::build_nested_call_tree(ast, lang, code, anchor, extra)
    } else {
        None
    };

    // Extract condition metadata for If nodes.  Python `elif_clause` and PHP
    // `else_if_clause` are lowered as guard nodes by `build_alternative_chain`
    // (the flat-sibling elif-chain handler) and carry their own `condition`
    // field, so they must also receive condition-metadata extraction even
    // though their grammar kind maps to `Kind::Block`.  These two node kinds
    // only ever reach `push_node` from that handler, so widening the guard
    // here cannot affect ordinary block lowering.
    let (condition_text, condition_vars, condition_negated, cond_arith, null_check) =
        if matches!(lookup_node(lang, ast), Kind::If)
            || matches!(ast.fkind(), "elif_clause" | "else_if_clause")
        {
            extract_condition_raw(ast, lang, code)
        } else {
            (None, Vec::new(), false, None, None)
        };

    // Detect parameterized SQL queries: arg 0 is a string literal with
    // placeholder patterns ($1, ?, %s, :name) and >= 2 args present.
    // Uses a deeper recursive search than `call_ast` (which only goes 2
    // levels) to handle await-wrapped calls inside declarations.
    let param_query_call = if labels
        .iter()
        .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SQL_QUERY)))
    {
        call_ast.or_else(|| scope.and_then(|s| find_call_node_deep(s, lang, 5)))
    } else {
        None
    };
    let mut param_query_call = param_query_call;
    let mut param_query_shape = param_query_call
        .map(|cn| parameterized_query_shape(cn, code))
        .unwrap_or(ParamQueryShape::NotParameterized);
    // A SQL sink in the middle of a call chain (`scope.where("a = ?", x).
    // order(:id)`): the node's outer call is the chain's last call, but the
    // sink is the inner call that supplied the callee.  Read the query shape
    // off that call.
    if param_query_shape == ParamQueryShape::NotParameterized
        && param_query_call.is_some()
        && let Some((s, e)) = inner_callee_span
        && let Some(mut inner) = ast.descendant_for_byte_range(s, e)
    {
        while (inner.start_byte(), inner.end_byte()) != (s, e) {
            match inner.parent() {
                Some(p) => inner = p,
                None => break,
            }
        }
        if (inner.start_byte(), inner.end_byte()) == (s, e) {
            let shape = parameterized_query_shape(inner, code);
            if shape != ParamQueryShape::NotParameterized {
                param_query_shape = shape;
                param_query_call = Some(inner);
            }
        }
    }
    let parameterized_query = param_query_shape == ParamQueryShape::ConstantQuery;
    let parameterized_query_interpolated = param_query_shape == ParamQueryShape::InterpolatedQuery;

    // An interpolated query with a params argument
    // (`cur.execute(f"... ORDER BY {sort} LIMIT ?", (n,))`) keeps its sink,
    // but only the query text is the payload.  The bound values are
    // parameters, the same way a gated `cursor.execute` / `pool.query` only
    // checks arg 0.  Do not override a gate that already chose its positions.
    let narrowed_query_call = if parameterized_query_interpolated
        && sink_payload_args.is_none()
        && gate_filters.is_empty()
    {
        sink_payload_args = Some(vec![0]);
        param_query_call
    } else {
        None
    };

    // Extract per-argument identifiers for Call nodes.
    // Also extract for gated-sink nodes so payload-arg filtering works.
    // A C / C++ branch or loop header whose condition calls something
    // (`if (!realpath(a, b))`, `while ((n = read(fd, buf, len)) > 0)`) needs
    // the per-argument groups too, so output-argument positions resolve.
    let c_header_call = header.is_some() && callee.is_some() && matches!(lang, "c" | "cpp");
    let arg_uses = if php_test_in_output {
        // The `isset` call is not the callee, so its arguments are not the
        // echo's arguments.
        Vec::new()
    } else if kind == StmtKind::Call || sink_payload_args.is_some() || c_header_call {
        call_ast
            .or(narrowed_query_call)
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
    // Constant head of each argument built from a literal prefix, for sinks
    // and URL builders whose URL is not the first argument.  Only SSRF /
    // open-redirect reasoning reads it, and only the call-site languages the
    // prefix extractor covers produce one.
    let arg_string_prefixes = if matches!(
        lang,
        "javascript" | "typescript" | "java" | "go" | "php" | "ruby" | "python" | "rust"
    ) {
        call_ast
            .map(|cn| extract_arg_string_prefixes(cn, lang, code))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let arg_bare_names = call_ast.map(extract_arg_bare_name_mask).unwrap_or(0);
    let arg_raw_string_mask = if lang == "go" {
        call_ast.map(extract_arg_raw_string_mask).unwrap_or(0)
    } else {
        0
    };

    let cond_call = if cond_call_text && kind == StmtKind::If {
        call_ast
            .filter(|cn| scope.is_none_or(|root| runs_unconditionally(root, *cn)))
            .map(|cn| {
                Box::new(CondCall {
                    callee: text.clone(),
                    arg_uses: extract_arg_uses(cn, code),
                })
            })
    } else {
        None
    };

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

    let kw_arg_positions = if lang == "ruby" && kind == StmtKind::Call {
        call_ast
            .map(|cn| literals::extract_ruby_kw_arg_positions(cn, code))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Check whether all arguments are syntactic literals (for taint sink suppression).
    let all_args_literal = if kind == StmtKind::Call && !rust_call_rebound {
        call_ast
            .map(|cn| has_only_literal_args(cn, code))
            .unwrap_or(false)
    } else {
        false
    };

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
        let assign_node = if matches!(lookup_node(lang, ast), Kind::Assignment) {
            Some(ast)
        } else if matches!(lookup_node(lang, ast), Kind::CallWrapper) {
            let mut cursor = ast.walk();
            ast.children(&mut cursor)
                .find(|c| matches!(lookup_node(lang, c), Kind::Assignment))
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
        match lookup_node(lang, cn) {
            Kind::CallMethod => {
                let recv_node = cn
                    .child_by_field_name("object")
                    .or_else(|| cn.child_by_field_name("receiver"))
                    .or_else(|| cn.child_by_field_name("scope"))
                    // Rust `method_call_expression` names the receiver "value".
                    .or_else(|| cn.child_by_field_name("value"));
                if let Some(rn) = recv_node
                    && matches!(rn.fkind(), "identifier" | "variable_name")
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
                    Some(fc) if fc.fkind() == "member_expression" || fc.fkind() == "attribute" => {
                        fc.child_by_field_name("object")
                    }
                    Some(fc) if fc.fkind() == "field_expression" => fc.child_by_field_name("value"),
                    Some(fc) if fc.fkind() == "selector_expression" => {
                        fc.child_by_field_name("operand")
                    }
                    _ => None,
                };
                if let Some(rn) = recv_node {
                    if matches!(rn.fkind(), "identifier" | "variable_name" | "this" | "self") {
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
    let cast_target_type = match ast.fkind() {
        // Java: (Type) expr
        "cast_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.fkind(), "type_identifier" | "scoped_type_identifier"))
            .and_then(|n| text_of(n, code)),
        // TypeScript: expr as Type
        "as_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.fkind(), "type_identifier" | "predefined_type"))
            .and_then(|n| text_of(n, code)),
        // TypeScript: <Type>expr (angle-bracket syntax)
        "type_assertion" => ast
            .child(0)
            .filter(|n| matches!(n.fkind(), "type_identifier" | "predefined_type"))
            .and_then(|n| text_of(n, code)),
        // Go: expr.(Type)
        "type_assertion_expression" => ast
            .child_by_field_name("type")
            .filter(|n| matches!(n.fkind(), "type_identifier" | "qualified_type"))
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
                .any(|ch| ch.fkind() == "do_block" || ch.fkind() == "block")
        });

    // The URL-bearing argument is the sink's lowest payload position
    // (`http.NewRequest(method, url, body)` pins arg 1), else the first.
    let url_arg = sink_payload_args
        .as_deref()
        .and_then(|p| p.iter().copied().filter(|&i| i != usize::MAX).min())
        .unwrap_or(0);
    // A read-modify-write keeps the target's own prefix (`url += "/x"`), so
    // only a call argument's prefix is recorded for it.
    let own_scope = if rmw.is_some() { None } else { scope };
    // The operands are found once per side and read for both the literal
    // prefix and, failing that, the leading module-constant identifier.  The
    // call side is only needed when the statement side has no prefix.
    let scope_ops = own_scope
        .map(|s| url_operand_nodes(s, lang, url_arg))
        .unwrap_or_default();
    let scope_prefix = template_prefix_of(&scope_ops, lang, code);
    let call_ops = match (&scope_prefix, call_ast) {
        (None, Some(cn)) => url_operand_nodes(cn, lang, url_arg),
        _ => SmallVec::new(),
    };
    let string_prefix = scope_prefix.or_else(|| template_prefix_of(&call_ops, lang, code));
    let string_concat_tail = rmw.is_none()
        && go_concat_operand
            .as_ref()
            .zip(string_prefix.as_deref())
            .is_some_and(|((lit, _), prefix)| lit == prefix);
    let url_sink = labels
        .iter()
        .any(|l| matches!(l, DataLabel::Sink(c) if c.intersects(Cap::SSRF | Cap::OPEN_REDIRECT)));
    let string_prefix_ident = if string_prefix.is_none() {
        lead_ident_of(&scope_ops, lang, code, url_sink)
            .or_else(|| lead_ident_of(&call_ops, lang, code, url_sink))
    } else {
        None
    };

    let (bin_op, bin_op_const) = match &rmw {
        Some(r) => {
            let op = rmw_bin_op(r.op, lang);
            (op, op.and_then(|_| rmw_bin_op_const(r, code)))
        }
        None => (
            extract_bin_op(ast, lang),
            extract_bin_op_const(ast, lang, code),
        ),
    };

    // Prefer the span of the call found by `find_classifiable_inner_call`
    // (deeper, classification-driven) over the one from `first_call_ident`
    // (shallower, text-override-driven).  Only record `callee_span` when it
    // actually narrows against `ast.span`, storing a redundant copy would
    // just bloat every labeled Call node.
    let callee_span = inner_callee_span.or(inner_text_span).filter(|s| *s != span);
    let callee_nesting =
        if text_from_member_label && inner_callee_span.is_none() && outer_callee.is_some() {
            CalleeNesting::Hoisted
        } else {
            callee_span.map_or(CalleeNesting::Own, |cs| call_arg_nesting(ast, cs))
        };

    // Constructor detection: a `new X(...)` call carries different cap
    // semantics than a plain function call. The SSA Call transfer uses
    // this flag to narrow the constructed value's caps so out-of-process
    // side-effect bits (FILE_IO, FMT_STRING, URL_ENCODE, JSON_PARSE) on
    // the arguments don't survive into a wrapper-object instance.
    // Recognised forms:
    //   * JS/TS `new_expression`
    //   * Java/C++ `object_creation_expression`
    //   * PHP `object_creation_expression`
    let is_constructor = ast.fkind() == "new_expression"
        || ast.fkind() == "object_creation_expression"
        || call_ast.is_some_and(|cn| {
            matches!(cn.fkind(), "new_expression" | "object_creation_expression")
        });

    let ctor_owned_args = collect_ctor_owned_args(ast, call_ast, lang, code, is_constructor);
    let new_into_smart_pointer =
        lang == "cpp" && text == "new" && cpp_decl_is_smart_pointer(ast, code);

    // Detect `Object.create(null)` so TypeFacts can tag the returned
    // SsaValue with `NullPrototypeObject` for flow-sensitive
    // prototype-pollution suppression.  Restricted to JS/TS where
    // `Object.create` is the idiomatic null-prototype constructor.
    let produces_null_proto = matches!(lang, "javascript" | "typescript")
        && call_ast.is_some_and(|cn| is_object_create_null_call(cn, code));

    // Java receivers typed only by a declaration (injected fields, formals,
    // locals bound to an untyped call).  Skipped when the node already has a
    // sink: type-qualified resolution only runs on calls with none.  The one
    // Java exception is a node whose sinks are all response-write sinks
    // (`println` / `write`): the declared type lets the taint engine drop the
    // cap when the receiver is plainly not an HTTP response (a `PrintStream`).
    let receiver_decl_type = match lang {
        "java" if labels.iter().all(html_escape_only_sink_or_non_sink) => {
            call_ast.and_then(|cn| java_call_receiver_decl_type(cn, code))
        }
        "rust" if !labels.iter().any(|l| matches!(l, DataLabel::Sink(_))) => {
            call_ast.and_then(|cn| rust_receivers::call_receiver_decl_type(cn, code))
        }
        _ => None,
    };

    let return_escapes = if kind == StmtKind::Return {
        helpers::collect_return_escapes(ast, lang, code)
    } else {
        helpers::ReturnEscapes::default()
    };

    let numeric_confined_uses = scope
        .map(|s| collect_numeric_confined_value_idents(s, lang, code, &labels))
        .unwrap_or_default();
    // Only Rust format-macro confined sinks need the phantom-ident skip list
    // (see [`NodeInfo::format_macro_method_idents`]); skip the walk otherwise.
    let format_macro_method_idents = if lang == "rust" && !numeric_confined_uses.is_empty() {
        scope.map_or_else(Vec::new, |s| collect_format_macro_method_idents(s, code))
    } else {
        Vec::new()
    };

    let elem_reads = if lang == "go" {
        go_elem_read_scope(ast, matches!(lookup_node(lang, ast), Kind::If))
            .map(|n| go_const_index_reads(n, code))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let map_stores = if lang == "go" {
        go_map_stores(ast, code)
    } else {
        Vec::new()
    };
    let mut condition_vars = condition_vars;
    if matches!(lookup_node(lang, ast), Kind::If) {
        condition_vars.extend(elem_reads.iter().map(|e| e.to_string()));
    }
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
            sink_reaching_uses,
            kwargs,
            kw_arg_positions,
            arg_string_literals,
            arg_string_prefixes,
            arg_bare_names,
            arg_raw_string_mask,
            destination_uses,
            gate_filters,
            is_constructor,
            callee_nesting,
            ctor_owned_args,
            produces_null_proto,
            hoisted_sink,
            nested_calls,
            receiver_decl_type,
        },
        taint: TaintMeta {
            labels,
            const_text,
            const_collection,
            defines,
            uses,
            extra_defines,
            array_pattern_indices,
            rhs_array_elements,
            rhs_object_literal,
        },
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        condition_text,
        condition_vars,
        condition_negated,
        null_check,
        cond_call,
        returned_idents: return_escapes.idents,
        returned_call_callees: return_escapes.call_callees,
        implicit_return: false,
        escaping_store: assignment_target_is_indirect(ast, lang),
        rhs_shape: if matches!(lang, "c" | "cpp") {
            rhs_shape_of(ast)
        } else {
            RhsShape::Whole
        },
        aliased_def: false,
        cond_arith,
        all_args_literal,
        catch_param: false,
        arg_callees,
        cast_target_type,
        bin_op,
        bin_op_const,
        rmw_assign: rmw.is_some(),
        rmw_rhs_from_pred: false,
        finally_return: false,
        finally_tail: false,
        managed_resource: is_raii_managed || is_ruby_block_managed || new_into_smart_pointer,
        borrowed_resource: lang == "java"
            && code
                .get(span.0..span.1)
                .is_some_and(|s| s.windows(13).any(|w| w == b"getConnection"))
            && java_getconnection_receiver_is_borrowed(ast, code),
        in_defer: false,
        parameterized_query,
        parameterized_query_interpolated,
        string_prefix,
        string_concat_tail,
        string_prefix_ident,
        root_unterminated: false,
        is_eq_with_const: rmw.is_none() && detect_eq_with_const(ast, lang),
        yields_number,
        is_numeric_length_access: rmw.is_none() && detect_numeric_length_access(ast, lang, code),
        member_field: if rmw.is_none() {
            detect_member_field_assignment(ast, code)
        } else {
            None
        },
        rhs_is_function_literal: rhs_is_function_literal(ast, lang),
        is_await_forward: lookup_node(lang, ast) == Kind::AwaitForward,
        decl_type: extract_decl_type(ast, lang, code),
        numeric_confined_uses,
        format_macro_method_idents,
        membership_lookup: if lang == "go" {
            extract_go_membership_lookup(ast, code)
        } else {
            None
        },
        is_ternary_condition: false,
        index_read_key: if rmw.is_none() {
            plain_index_read_key(ast, code)
        } else {
            None
        },
        elem_reads,
        elem_base_unstable: false,
        map_stores,
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

/// Simple leaf name of a Java type text: strip generic arguments
/// (`Session<T>` → `Session`), array brackets (`Foo[]` → `Foo`), and any
/// package qualifier (`liquibase.database.Database` → `Database`).
pub(crate) fn java_type_leaf(type_text: &str) -> &str {
    let no_generics = type_text.split('<').next().unwrap_or(type_text);
    let no_array = no_generics.split('[').next().unwrap_or(no_generics);
    no_array.rsplit('.').next().unwrap_or(no_array).trim()
}

/// Whether a Java type is a *borrowed-owner* of the JDBC `Connection` it
/// yields via `getConnection()`: a managed session / DB abstraction that
/// closes the connection as part of its own lifecycle, so a body that
/// borrows the connection must NOT close it.  Recognised owners:
///   * Liquibase `liquibase.database.Database`
///   * Hibernate `org.hibernate.Session` / `StatelessSession` /
///     `SharedSessionContract(Implementor)` / `SessionImplementor`
///   * MyBatis `org.apache.ibatis.session.SqlSession` / `SqlSessionManager`
///   * JPA `jakarta/javax.persistence.EntityManager`
///
/// In contrast a `javax.sql.DataSource` / `java.sql.DriverManager`
/// `getConnection(...)` returns an OWNED connection the caller must close —
/// those are NOT in this set (they do not end in `Session` and are not
/// listed), so their leaks stay true positives.
///
/// A leaf name ending in `Session` (Hibernate `Session` / `StatelessSession`,
/// MyBatis `SqlSession`, sonarqube `DbSession`, …) is treated as a managed
/// DB session that owns its connection.  This is sound in context: the flag
/// is consulted only at a `getConnection()` receiver, and the only types that
/// ever appear there are DB-connection-owning types (a servlet `HttpSession`
/// has no `getConnection`, so it never matters).  `Database` is matched
/// exactly (Liquibase's interface) rather than by suffix, to avoid
/// suppressing a homegrown `*Database` wrapper whose `getConnection()`
/// freshly opens an OWNED connection.
fn is_java_borrowed_connection_owner(type_text: &str) -> bool {
    let leaf = java_type_leaf(type_text);
    leaf.ends_with("Session")
        || matches!(
            leaf,
            "Database"                          // Liquibase liquibase.database.Database
                | "SharedSessionContract"       // Hibernate contracts (non-`Session` suffix)
                | "SharedSessionContractImplementor"
                | "SessionImplementor"
                | "SqlSessionManager"           // MyBatis session manager
                | "EntityManager" // JPA jakarta/javax.persistence.EntityManager
        )
}

/// Whether the acquire statement `ast` is a Java `X.getConnection()` whose
/// receiver `X` has a statically-declared *borrowed-owner* type (see
/// [`is_java_borrowed_connection_owner`]).  The receiver's declared type is
/// resolved from the enclosing method's formal parameters, then a preceding
/// typed local declaration in the same scope, then the enclosing class's
/// fields — Java is statically typed so exactly one of these carries the
/// declaration.
///
/// Recall-preserving: returns `true` only when the receiver type is a
/// positively-recognised borrowed owner.  A static factory call
/// (`DriverManager.getConnection(...)`, whose receiver `DriverManager`
/// resolves to no local / parameter / field), a `DataSource` receiver, and a
/// bare `getConnection()` all return `false`, so those leaks stay reported.
///
/// Motivated by the openmrs Liquibase changeset shape
/// `execute(Database database) { … database.getConnection() }`, where
/// Liquibase owns and closes the connection.
fn java_getconnection_receiver_is_borrowed(ast: Node, code: &[u8]) -> bool {
    let Some(mi) = find_java_getconnection_invocation(ast, code) else {
        return false;
    };
    // No receiver (`getConnection()` bare) → nothing to type.
    let Some(obj) = mi.child_by_field_name("object") else {
        return false;
    };
    let Some(recv) = java_receiver_var_name(obj, code) else {
        return false;
    };
    match resolve_java_var_declared_type(mi, &recv, code) {
        Some(ty) => is_java_borrowed_connection_owner(&ty),
        None => false,
    }
}

/// The receiver variable name of a Java method-invocation `object` node.
/// Plain `identifier` → its text.  `this.field` / `obj.field`
/// (`field_access`) → the accessed field name.  Any more complex receiver
/// (chained call, array access, …) → `None`.
fn java_receiver_var_name(obj: Node, code: &[u8]) -> Option<String> {
    match obj.fkind() {
        "identifier" => text_of(obj, code),
        "field_access" => obj
            .child_by_field_name("field")
            .and_then(|f| text_of(f, code)),
        _ => None,
    }
}

/// Where the bytes behind a Java stream expression come from, as far as the
/// expression and the declarations in the same method show.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum JavaStreamRoot {
    /// `Process.getInputStream()` and friends: output of a child process.
    Process,
    /// Classpath / zip entries and Spring `*Resource` objects: files that
    /// ship with the application.
    LocalResource,
    /// An `HttpServletRequest`-like receiver.  Its `getInputStream()` /
    /// `getReader()` is the source and `readLine()` on what it returns
    /// carries that taint by propagation.
    Request,
    /// Anything else, including everything the file does not settle.
    Other,
}

/// Wrapper streams that read from their first constructor argument.
fn java_is_stream_wrapper(leaf: &str) -> bool {
    matches!(
        leaf,
        "BufferedReader"
            | "InputStreamReader"
            | "LineNumberReader"
            | "PushbackReader"
            | "Scanner"
            | "BufferedInputStream"
            | "DataInputStream"
            | "PushbackInputStream"
            | "GZIPInputStream"
            | "InflaterInputStream"
    )
}

fn java_type_stream_root(type_text: &str) -> JavaStreamRoot {
    let leaf = java_type_leaf(type_text);
    if leaf == "Process" {
        JavaStreamRoot::Process
    } else if matches!(
        leaf,
        "ZipFile"
            | "JarFile"
            | "Resource"
            | "ClassPathResource"
            | "FileSystemResource"
            | "PathResource"
            | "ByteArrayResource"
            | "ServletContextResource"
    ) {
        JavaStreamRoot::LocalResource
    } else if leaf.ends_with("Request") || leaf.ends_with("RequestWrapper") {
        JavaStreamRoot::Request
    } else {
        JavaStreamRoot::Other
    }
}

/// Initialiser expression of local variable `var` in the Java scopes
/// enclosing `from`: a block-level declaration or a try-with-resources
/// binding.  Formals, fields and loop variables have none.
fn java_local_initializer<'a>(from: Node<'a>, var: &str, code: &[u8]) -> Option<Node<'a>> {
    let mut cur = from;
    while let Some(parent) = cur.parent() {
        match parent.fkind() {
            "block" | "constructor_body" => {
                let mut cursor = parent.walk();
                for decl in parent.named_children(&mut cursor) {
                    if decl.fkind() != "local_variable_declaration" {
                        continue;
                    }
                    let mut c2 = decl.walk();
                    for d in decl.children(&mut c2) {
                        if d.fkind() == "variable_declarator"
                            && d.child_by_field_name("name")
                                .and_then(|n| n.utf8_text(code).ok())
                                == Some(var)
                        {
                            return d.child_by_field_name("value");
                        }
                    }
                }
            }
            "try_with_resources_statement" => {
                if let Some(specs) = parent.child_by_field_name("resources") {
                    let mut cursor = specs.walk();
                    for res in specs.named_children(&mut cursor) {
                        if res.fkind() == "resource"
                            && res
                                .child_by_field_name("name")
                                .and_then(|n| n.utf8_text(code).ok())
                                == Some(var)
                        {
                            return res.child_by_field_name("value");
                        }
                    }
                }
            }
            "method_declaration" | "constructor_declaration" | "lambda_expression" => {
                return None;
            }
            _ => {}
        }
        cur = parent;
    }
    None
}

/// Classify a Java stream expression.  `depth` bounds the walk through
/// wrapper constructors and local initialisers.
fn java_stream_root(expr: Node, code: &[u8], depth: u8) -> JavaStreamRoot {
    if depth == 0 {
        return JavaStreamRoot::Other;
    }
    match expr.fkind() {
        "parenthesized_expression" => expr.named_child(0).map_or(JavaStreamRoot::Other, |e| {
            java_stream_root(e, code, depth - 1)
        }),
        "object_creation_expression" => {
            let Some(leaf) = expr
                .child_by_field_name("type")
                .and_then(|t| text_of(t, code))
            else {
                return JavaStreamRoot::Other;
            };
            let leaf = java_type_leaf(&leaf).to_string();
            if java_is_stream_wrapper(&leaf) {
                expr.child_by_field_name("arguments")
                    .and_then(|a| a.named_child(0))
                    .map_or(JavaStreamRoot::Other, |a| {
                        java_stream_root(a, code, depth - 1)
                    })
            } else {
                java_type_stream_root(&leaf)
            }
        }
        "method_invocation" => {
            let name = expr
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(code).ok())
                .unwrap_or("");
            match name {
                "exec" | "start" => JavaStreamRoot::Process,
                "getResourceAsStream" => JavaStreamRoot::LocalResource,
                "getInputStream" | "getReader" | "getErrorStream" => expr
                    .child_by_field_name("object")
                    .map_or(JavaStreamRoot::Other, |o| {
                        java_stream_root(o, code, depth - 1)
                    }),
                _ => JavaStreamRoot::Other,
            }
        }
        "identifier" => {
            let Some(var) = text_of(expr, code) else {
                return JavaStreamRoot::Other;
            };
            if let Some(ty) = resolve_java_var_declared_type(expr, &var, code)
                && java_type_leaf(&ty) != "var"
            {
                let root = java_type_stream_root(&ty);
                if root != JavaStreamRoot::Other {
                    return root;
                }
            }
            // A wrapper-typed or `var` local takes the root of what it was
            // built from.
            java_local_initializer(expr, &var, code).map_or(JavaStreamRoot::Other, |init| {
                java_stream_root(init, code, depth - 1)
            })
        }
        _ => JavaStreamRoot::Other,
    }
}

/// Every `method_invocation` under `ast` named `name`, outermost first,
/// without entering lambdas, nested classes or method declarations.
fn find_java_invocation_named<'a>(ast: Node<'a>, name: &str, code: &[u8]) -> Vec<Node<'a>> {
    fn walk<'a>(n: Node<'a>, name: &str, code: &[u8], out: &mut Vec<Node<'a>>) {
        if n.fkind() == "method_invocation"
            && n.child_by_field_name("name")
                .and_then(|m| m.utf8_text(code).ok())
                == Some(name)
        {
            out.push(n);
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if matches!(
                child.fkind(),
                "lambda_expression" | "class_body" | "method_declaration"
            ) {
                continue;
            }
            walk(child, name, code, out);
        }
    }
    let mut out = Vec::new();
    walk(ast, name, code, &mut out);
    out
}

/// Whether `call` can be `java.lang.Class.getMethod` / `getDeclaredMethod`:
/// it names a method (one argument or more) on a receiver that can hold a
/// `Class`.  `Class` is final, so an unqualified call, a `this.` / `super.`
/// call and a call on a receiver declared as another type are the
/// enclosing code's own helpers or other APIs (`ZipEntry.getMethod()`).  A
/// bare class name receiver (`Util.getMethod(..)`) is a static helper.
/// Receivers the file does not settle stay plausible.
fn java_may_be_class_method_lookup(call: Node, code: &[u8]) -> bool {
    let has_name_arg = call
        .child_by_field_name("arguments")
        .is_some_and(|a| a.named_child(0).is_some());
    if !has_name_arg {
        return false;
    }
    let Some(object) = call.child_by_field_name("object") else {
        return false;
    };
    match object.fkind() {
        "this" | "super" => false,
        "identifier" | "field_access" => match java_receiver_declared_type(call, code) {
            Some(ty) => {
                let leaf = java_type_leaf(&ty);
                leaf == "Class"
                    || leaf == "var"
                    || (leaf.len() <= 2 && leaf.chars().all(|c| c.is_ascii_uppercase()))
            }
            None => {
                !(object.fkind() == "identifier"
                    && object.utf8_text(code).is_ok_and(|t| {
                        t.starts_with(|c: char| c.is_ascii_uppercase())
                            && t.chars().any(|c| c.is_ascii_lowercase())
                    }))
            }
        },
        _ => true,
    }
}

/// Drop the reflective-lookup gate match when no `getMethod` /
/// `getDeclaredMethod` call in the statement can be `Class.getMethod`.  The
/// gate is keyed on the callee name, which user helpers and unrelated APIs
/// share.
fn java_veto_non_reflective_lookup(
    ast: Node,
    callee_text: &str,
    code: &[u8],
    matches: &mut SmallVec<[crate::labels::GateMatch; 2]>,
) {
    let leaf = callee_text.rsplit('.').next().unwrap_or(callee_text);
    if !matches!(leaf, "getMethod" | "getDeclaredMethod") {
        return;
    }
    let calls = find_java_invocation_named(ast, leaf, code);
    if !calls.is_empty()
        && !calls
            .iter()
            .any(|c| java_may_be_class_method_lookup(*c, code))
    {
        matches.retain(
            |g| !matches!(g.label, DataLabel::Sink(c) if c.contains(crate::labels::Cap::CODE_EXEC)),
        );
    }
}

/// Whether the Java call `call` is a stream accessor whose `Source` label
/// does not apply.
///
/// `getInputStream` / `getReader` are request accessors by name, but the same
/// names read a child process's output and classpath or zip entries.  Those
/// are local data, not input.  `readLine` is a file-content source on its own
/// (a config file read into a command is the engine's FileSystem model), but
/// not when its reader is built on a process, a local resource, or the
/// request itself.  The request case keeps its flow: the reader's receiver
/// taint, which comes from the `getInputStream` / `getReader` source,
/// propagates into the line, and the source stays attributed to the request
/// instead of to a generic file read.  A receiver the file does not settle
/// keeps the label.
pub(super) fn java_stream_source_is_local(call: Node, code: &[u8]) -> bool {
    if call.fkind() != "method_invocation" {
        return false;
    }
    let Some(name) = call
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(code).ok())
    else {
        return false;
    };
    if !matches!(name, "getInputStream" | "getReader" | "readLine") {
        return false;
    }
    let Some(object) = call.child_by_field_name("object") else {
        return false;
    };
    let root = java_stream_root(object, code, 6);
    match name {
        "readLine" => matches!(
            root,
            JavaStreamRoot::Process | JavaStreamRoot::LocalResource | JavaStreamRoot::Request
        ),
        _ => matches!(
            root,
            JavaStreamRoot::Process | JavaStreamRoot::LocalResource
        ),
    }
}

/// Service kind of a Java declared receiver type, for type-qualified label
/// resolution on receivers whose type is only visible in a declaration: an
/// injected field (`private JdbcTemplate jdbc;`), a formal
/// (`void f(DirContext ctx)`), or a local bound to an untyped call
/// (`DirContext c = lookup();`).  Only library service types whose
/// `TypeKind` prefixes label rules are mapped.  Value and stream types
/// (`String`, `Writer`, `HttpServletResponse`) are not: a declared
/// `PrintWriter out` is normally the servlet response writer, whose
/// `println` must stay an XSS sink, and `HttpResponse` would also match
/// `java.net.http.HttpResponse`.
pub(crate) fn java_declared_receiver_kind(
    type_text: &str,
) -> Option<crate::ssa::type_facts::TypeKind> {
    use crate::ssa::type_facts::TypeKind;
    let leaf = java_type_leaf(type_text);
    match leaf {
        "JdbcTemplate"
        | "NamedParameterJdbcTemplate"
        | "JdbcOperations"
        | "NamedParameterJdbcOperations" => Some(TypeKind::JdbcTemplate),
        // JPA `EntityManager` has the same `createQuery` /
        // `createNativeQuery` statement API as the Hibernate session.
        "Session" | "StatelessSession" | "EntityManager" => Some(TypeKind::HibernateSession),
        "CallableStatement" => Some(TypeKind::DatabaseConnection),
        // Output streams and writers that sit on a file or memory buffer.
        // `PrintStream` / `DataOutputStream` / `ObjectOutputStream` are left
        // out too: they wrap any stream, including the servlet response
        // (`new PrintStream(resp.getOutputStream())`).  `PrintWriter` /
        // `Writer` / `OutputStream` / `ServletOutputStream` /
        // `BufferedWriter` are left out because servlet code declares the
        // response writer with those types.
        "FileOutputStream" | "FileWriter" | "ByteArrayOutputStream" | "StringWriter" => {
            Some(TypeKind::FileHandle)
        }
        "ProcessBuilder" => Some(TypeKind::ProcessBuilder),
        "StringBuilder" | "StringBuffer" => Some(TypeKind::StringBuilder),
        // Parser factories: `dbf.newDocumentBuilder().parse(x)` reads as
        // `dbf.parse`, and StAX parses straight off the factory
        // (`xif.createXMLStreamReader(in)`).
        "SAXReader" | "XMLInputFactory" | "DocumentBuilderFactory" | "SAXParserFactory" => {
            Some(TypeKind::XmlParser)
        }
        _ => match crate::constraint::solver::class_name_to_type_kind(leaf)? {
            k @ (TypeKind::HttpClient
            | TypeKind::DatabaseConnection
            | TypeKind::LdapClient
            | TypeKind::XPathClient
            | TypeKind::XmlParser
            | TypeKind::Template
            | TypeKind::Runtime) => Some(k),
            _ => None,
        },
    }
}

/// True for labels that leave a Java call node open to declared-type receiver
/// resolution: anything that is not a sink, or a sink carrying only
/// `HTML_ESCAPE`.
fn html_escape_only_sink_or_non_sink(label: &DataLabel) -> bool {
    match label {
        DataLabel::Sink(caps) => *caps == Cap::HTML_ESCAPE,
        _ => true,
    }
}

/// Declared service kind of the receiver of a Java `method_invocation`: a
/// plain identifier resolved through the enclosing scopes, or `this.f`
/// resolved against the enclosing class fields.  A class name used as a
/// static receiver (`Files.readString`) binds no variable and gives `None`.
fn java_call_receiver_decl_type(
    call: Node,
    code: &[u8],
) -> Option<crate::ssa::type_facts::TypeKind> {
    let ty = java_receiver_declared_type(call, code)?;
    if let Some(kind) = java_declared_receiver_kind(&ty) {
        return Some(kind);
    }
    // A wrapping stream (`PrintStream`, `PrintWriter`, ...) can sit on the
    // servlet response, so its declared type alone says nothing.  When the
    // variable is bound once to a constructor chain that bottoms out in a
    // file or memory stream (`new PrintStream(new FileOutputStream(f))`), it
    // is a file writer.
    (java_is_wrapping_stream_type(&ty) && java_receiver_wraps_file_stream(call, code))
        .then_some(crate::ssa::type_facts::TypeKind::FileHandle)
}

/// Java stream and writer types that wrap another stream or writer.
fn java_is_wrapping_stream_type(ty: &str) -> bool {
    matches!(
        ty.rsplit('.').next().unwrap_or(ty),
        "PrintStream"
            | "PrintWriter"
            | "DataOutputStream"
            | "ObjectOutputStream"
            | "BufferedOutputStream"
            | "BufferedWriter"
            | "OutputStreamWriter"
    )
}

/// Whether the identifier receiver of a Java `method_invocation` is bound,
/// exactly once, to a constructor chain of wrapping streams around a file or
/// memory stream: a `try (T x = new ...)` resource, or a block local with no
/// later reassignment.  Anything else (a formal, a field, a reassigned local,
/// an initializer that is not a constructor) gives `false`.
fn java_receiver_wraps_file_stream(call: Node, code: &[u8]) -> bool {
    let Some(obj) = call.child_by_field_name("object") else {
        return false;
    };
    if obj.fkind() != "identifier" {
        return false;
    }
    let Some(var) = text_of(obj, code) else {
        return false;
    };
    let mut cur = call;
    while let Some(parent) = cur.parent() {
        match parent.fkind() {
            "try_with_resources_statement" => {
                if let Some(specs) = parent.child_by_field_name("resources") {
                    let mut cursor = specs.walk();
                    for res in specs.named_children(&mut cursor) {
                        if res.fkind() == "resource"
                            && res
                                .child_by_field_name("name")
                                .and_then(|n| n.utf8_text(code).ok())
                                == Some(var.as_str())
                        {
                            return res
                                .child_by_field_name("value")
                                .is_some_and(|v| java_ctor_chain_ends_in_file_stream(v, code));
                        }
                    }
                }
            }
            "block" | "constructor_body" => {
                let mut cursor = parent.walk();
                let decl = parent.named_children(&mut cursor).find(|c| {
                    c.fkind() == "local_variable_declaration"
                        && java_decl_defines_var(*c, &var, code)
                });
                if let Some(decl) = decl {
                    let mut c2 = decl.walk();
                    let value = decl
                        .named_children(&mut c2)
                        .filter(|d| d.fkind() == "variable_declarator")
                        .find(|d| {
                            d.child_by_field_name("name")
                                .and_then(|n| n.utf8_text(code).ok())
                                == Some(var.as_str())
                        })
                        .and_then(|d| d.child_by_field_name("value"));
                    return value.is_some_and(|v| java_ctor_chain_ends_in_file_stream(v, code))
                        && !java_subtree_assigns(parent, &var, code);
                }
            }
            "method_declaration"
            | "constructor_declaration"
            | "lambda_expression"
            | "class_body" => return false,
            _ => {}
        }
        cur = parent;
    }
    false
}

/// Whether `expr` is `new W(new W2(... new F(..)))`, every `W` a wrapping
/// stream and `F` a file or memory stream, the wrapped stream always being the
/// first constructor argument.
fn java_ctor_chain_ends_in_file_stream(expr: Node, code: &[u8]) -> bool {
    let mut cur = expr;
    for _ in 0..8 {
        if cur.fkind() != "object_creation_expression" {
            return false;
        }
        let Some(ty) = cur
            .child_by_field_name("type")
            .and_then(|t| text_of(t, code))
        else {
            return false;
        };
        let leaf = ty.rsplit('.').next().unwrap_or(&ty);
        if matches!(
            leaf,
            "FileOutputStream" | "FileWriter" | "ByteArrayOutputStream" | "StringWriter"
        ) {
            return true;
        }
        if !java_is_wrapping_stream_type(leaf) {
            return false;
        }
        let Some(first) = cur
            .child_by_field_name("arguments")
            .and_then(|a| a.named_child(0))
        else {
            return false;
        };
        cur = first;
    }
    false
}

/// Whether any assignment under `scope` writes the bare identifier `var`.
fn java_subtree_assigns(scope: Node, var: &str, code: &[u8]) -> bool {
    let mut stack = vec![scope];
    while let Some(n) = stack.pop() {
        if n.fkind() == "assignment_expression"
            && n.child_by_field_name("left")
                .is_some_and(|l| l.fkind() == "identifier" && l.utf8_text(code).ok() == Some(var))
        {
            return true;
        }
        let mut cursor = n.walk();
        stack.extend(n.named_children(&mut cursor));
    }
    false
}

/// Declared type text of the receiver of a Java `method_invocation`: a plain
/// identifier resolved through the enclosing scopes (formals, locals, `for` /
/// `catch` / `try` bindings, fields), or `this.f` resolved against the
/// enclosing class fields.  `None` for a static receiver (a class name binds
/// no variable), a chained or otherwise computed receiver, `var` locals
/// excepted: those return the literal text `var`.
pub(crate) fn java_receiver_declared_type(call: Node, code: &[u8]) -> Option<String> {
    if call.fkind() != "method_invocation" {
        return None;
    }
    let obj = call.child_by_field_name("object")?;
    match obj.fkind() {
        "identifier" => resolve_java_var_declared_type(call, &text_of(obj, code)?, code),
        "field_access"
            if obj
                .child_by_field_name("object")
                .is_some_and(|o| o.fkind() == "this") =>
        {
            let field = text_of(obj.child_by_field_name("field")?, code)?;
            resolve_java_field_declared_type(call, &field, code)
        }
        _ => None,
    }
}

/// Declared type of field `var` in the class enclosing `from` (the inner
/// class first, then outer classes).
fn resolve_java_field_declared_type(from: Node, var: &str, code: &[u8]) -> Option<String> {
    let mut cur = from;
    while let Some(parent) = cur.parent() {
        if matches!(
            parent.fkind(),
            "class_body" | "interface_body" | "enum_body"
        ) && let Some(t) = java_field_declared_type(parent, var, code)
        {
            return Some(t);
        }
        cur = parent;
    }
    None
}

/// Pre-order search for a `method_invocation` named `getConnection` within
/// (or equal to) `ast`.  Does not descend into nested method / lambda bodies
/// (those own their own scope and acquire nodes).  Returns the first match.
fn find_java_getconnection_invocation<'a>(ast: Node<'a>, code: &[u8]) -> Option<Node<'a>> {
    if ast.fkind() == "method_invocation"
        && ast
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(code).ok())
            == Some("getConnection")
    {
        return Some(ast);
    }
    let mut cursor = ast.walk();
    for child in ast.children(&mut cursor) {
        if matches!(child.fkind(), "method_declaration" | "lambda_expression") {
            continue;
        }
        if let Some(found) = find_java_getconnection_invocation(child, code) {
            return Some(found);
        }
    }
    None
}

/// Resolve the statically-declared type text of Java variable `var` as seen
/// from `from`, by walking up enclosing scopes: method / constructor / lambda
/// parameters, block-local declarations, then class / interface / enum
/// fields.  Returns the raw type text (leaf-simplified by the caller).
fn resolve_java_var_declared_type(from: Node, var: &str, code: &[u8]) -> Option<String> {
    let mut cur = from;
    while let Some(parent) = cur.parent() {
        match parent.fkind() {
            "method_declaration" | "constructor_declaration" | "lambda_expression" => {
                if let Some(t) = java_param_declared_type(parent, var, code) {
                    return Some(t);
                }
                // An untyped lambda formal (`jdbc -> jdbc.update(..)`) may
                // shadow a field of the same name; its type is unknown.
                if parent.fkind() == "lambda_expression"
                    && java_lambda_binds_untyped(parent, var, code)
                {
                    return None;
                }
            }
            // `for (T x : xs)` and `catch (T e)` bind their own variable.
            "enhanced_for_statement" => {
                if parent
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(code).ok())
                    == Some(var)
                {
                    return parent
                        .child_by_field_name("type")
                        .and_then(|t| text_of(t, code));
                }
            }
            "catch_clause" => {
                let mut cursor = parent.walk();
                if let Some(fp) = parent
                    .named_children(&mut cursor)
                    .find(|c| c.fkind() == "catch_formal_parameter")
                    && fp
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(code).ok())
                        == Some(var)
                {
                    let mut c2 = fp.walk();
                    return fp
                        .named_children(&mut c2)
                        .find(|c| c.fkind() == "catch_type")
                        .and_then(|t| text_of(t, code));
                }
            }
            // `try (T x = ...) { ... }`
            "try_with_resources_statement" => {
                if let Some(specs) = parent.child_by_field_name("resources") {
                    let mut cursor = specs.walk();
                    for res in specs.named_children(&mut cursor) {
                        if res.fkind() == "resource"
                            && res
                                .child_by_field_name("name")
                                .and_then(|n| n.utf8_text(code).ok())
                                == Some(var)
                        {
                            return res
                                .child_by_field_name("type")
                                .and_then(|t| text_of(t, code));
                        }
                    }
                }
            }
            "block" | "constructor_body" => {
                if let Some(t) = java_block_local_declared_type(parent, var, code) {
                    return Some(t);
                }
            }
            "class_body" | "interface_body" | "enum_body" => {
                if let Some(t) = java_field_declared_type(parent, var, code) {
                    return Some(t);
                }
            }
            _ => {}
        }
        cur = parent;
    }
    None
}

/// Declared type of formal parameter `var` on a Java method / constructor /
/// lambda node, if present.
fn java_param_declared_type(method: Node, var: &str, code: &[u8]) -> Option<String> {
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    for fp in params.named_children(&mut cursor) {
        if !matches!(fp.fkind(), "formal_parameter" | "spread_parameter") {
            continue;
        }
        if fp
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(code).ok())
            == Some(var)
        {
            return fp
                .child_by_field_name("type")
                .and_then(|t| text_of(t, code));
        }
    }
    None
}

/// Whether a Java lambda binds `var` as an untyped formal (`x -> ...`,
/// `(x, y) -> ...`).
fn java_lambda_binds_untyped(lambda: Node, var: &str, code: &[u8]) -> bool {
    let Some(params) = lambda.child_by_field_name("parameters") else {
        return false;
    };
    if params.fkind() == "identifier" {
        return params.utf8_text(code).ok() == Some(var);
    }
    let mut cursor = params.walk();
    params
        .named_children(&mut cursor)
        .any(|p| p.fkind() == "identifier" && p.utf8_text(code).ok() == Some(var))
}

/// Declared type of `var` among the direct `local_variable_declaration`
/// children of a Java block, if declared there.
fn java_block_local_declared_type(block: Node, var: &str, code: &[u8]) -> Option<String> {
    let mut cursor = block.walk();
    for child in block.named_children(&mut cursor) {
        if child.fkind() == "local_variable_declaration" && java_decl_defines_var(child, var, code)
        {
            return child
                .child_by_field_name("type")
                .and_then(|t| text_of(t, code));
        }
    }
    None
}

/// Declared type of field `var` among the `field_declaration` members of a
/// Java class / interface / enum body, if declared there.
fn java_field_declared_type(body: Node, var: &str, code: &[u8]) -> Option<String> {
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if child.fkind() == "field_declaration" && java_decl_defines_var(child, var, code) {
            return child
                .child_by_field_name("type")
                .and_then(|t| text_of(t, code));
        }
    }
    None
}

/// Whether a Java declaration node (`local_variable_declaration` /
/// `field_declaration`) declares a `variable_declarator` named `var`.
fn java_decl_defines_var(decl: Node, var: &str, code: &[u8]) -> bool {
    let mut cursor = decl.walk();
    decl.children(&mut cursor).any(|ch| {
        ch.fkind() == "variable_declarator"
            && ch
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(code).ok())
                == Some(var)
    })
}

/// Add the same edge (of the same kind) from every node in `froms` to `to`.
#[inline]
pub(super) fn connect_all(g: &mut Cfg, froms: &[NodeIndex], to: NodeIndex, kind: EdgeKind) {
    for &f in froms {
        debug!(target: "cfg", "edge {} → {} ({:?})", f.index(), to.index(), kind);
        g.add_edge(f, to, kind);
    }
}

/// Whether `ast` is (or holds) a `let` with a trait-object type annotation
/// whose initialiser starts with the decode call itself, so the annotation is
/// the decode target (`let v: Box<dyn P> = toml::from_str(s)?`, not a tuple or
/// a wrapper call that merely contains it).
fn rust_let_decodes_into_dyn(ast: Node, code: &[u8]) -> bool {
    let decl = if ast.fkind() == "let_declaration" {
        ast
    } else {
        let mut cursor = ast.walk();
        match ast
            .children(&mut cursor)
            .find(|c| c.fkind() == "let_declaration")
        {
            Some(d) => d,
            None => return false,
        }
    };
    let (Some(ty), Some(value)) = (
        decl.child_by_field_name("type"),
        decl.child_by_field_name("value"),
    ) else {
        return false;
    };
    let (Some(ty_text), Some(value_text)) = (text_of(ty, code), text_of(value, code)) else {
        return false;
    };
    crate::labels::rust_decode_target_is_dyn(&ty_text)
        && crate::labels::is_polymorphic_decode_head(
            value_text.split('(').next().unwrap_or("").trim(),
        )
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
/// Extract the declared type annotation of a Rust `let x: T = <rhs>` binding
/// and lower it to the lattice [`crate::ssa::type_facts::TypeKind`] for the
/// bound value.  Returns `None` for any non-Rust language, any node that is
/// not (or does not directly wrap) a `let_declaration` carrying a `type`
/// field, and any annotation the lattice does not recognise (see
/// [`crate::ssa::type_facts::rust_annotation_type_kind`]).
///
/// `ast` may be the `let_declaration` itself or a statement wrapper whose
/// direct child is the declaration (mirrors the RHS-locating walk in
/// [`rhs_is_function_literal`]).  Rust is the only language wired here: its
/// idiomatic binding RHS `str::parse` is the one verb whose return type is
/// ambiguous between numeric and non-numeric `FromStr` targets, so the
/// annotation is the only ground truth.
fn extract_decl_type(
    ast: Node,
    lang: &str,
    code: &[u8],
) -> Option<crate::ssa::type_facts::TypeKind> {
    if lang == "go" {
        return extract_decl_type_go(ast, code);
    }
    if lang != "rust" {
        return None;
    }
    let decl = if ast.fkind() == "let_declaration" {
        ast
    } else {
        let mut cursor = ast.walk();
        ast.children(&mut cursor)
            .find(|c| c.fkind() == "let_declaration")?
    };
    let type_node = decl.child_by_field_name("type")?;
    let type_text = text_of(type_node, code)?;
    crate::ssa::type_facts::rust_annotation_type_kind(&type_text)
}

/// Go local-binding type inference.
///
/// A local bound to a constructor, `buf := &bytes.Buffer{}`,
/// `stdIn := new(bytes.Buffer)`, `c := &http.Client{Timeout: t}`, or
/// declared with a type and no initialiser, `var sb strings.Builder`,
/// `var c http.Client`, has that type.  The type node is not a value use, so
/// without this the binding's `TypeFact` stays `Unknown`: the Go
/// `fmt.Fprint*` XSS gate cannot see that `fmt.Fprintf(&sb, ...)` writes to
/// a buffer (gitea `temp_repo.go` `fmt.Fprintf(stdIn, ...)`), and
/// `c.Get(u)` never reaches the `HttpClient.Get` SSRF gate.  The type text
/// goes through the shared [`params::go_decl_type_to_kind`] table, so only
/// byte writers, `http.ResponseWriter` and `http.Client` resolve.
///
/// A declared type with an initialiser (`var out io.Writer = w`) is not
/// used: the interface type says nothing about the value it holds.
fn extract_decl_type_go(ast: Node, code: &[u8]) -> Option<crate::ssa::type_facts::TypeKind> {
    let ty_text = match ast.fkind() {
        // `x := <rhs>` / `x = <rhs>`
        "short_var_declaration" | "assignment_statement" => {
            let right = ast.child_by_field_name("right")?;
            go_constructor_type_text(first_go_expr(right)?, code)?
        }
        // `var x T` / `var x = <rhs>`, possibly under a single-spec
        // `var_declaration`.
        "var_declaration" => {
            let mut cursor = ast.walk();
            let specs: Vec<Node> = ast
                .named_children(&mut cursor)
                .filter(|c| c.fkind() == "var_spec")
                .collect();
            if specs.len() != 1 {
                return None;
            }
            go_var_spec_type_text(specs[0], code)?
        }
        "var_spec" => go_var_spec_type_text(ast, code)?,
        _ => return None,
    };
    params::go_decl_type_to_kind(&ty_text)
}

/// Type text for one `var_spec`: the constructor type of its value when it
/// has one, otherwise the declared type of a zero-value declaration.
fn go_var_spec_type_text(spec: Node, code: &[u8]) -> Option<String> {
    match spec.child_by_field_name("value") {
        Some(value) => go_constructor_type_text(first_go_expr(value)?, code),
        None => text_of(spec.child_by_field_name("type")?, code),
    }
}

/// True when the writer argument (arg 0) of a Go `fmt.Fprint*` /
/// `io.WriteString` call is never an `http.ResponseWriter`: a stdlib stream
/// such as `os.Stderr` ([`crate::ssa::type_facts::is_go_non_response_writer`]),
/// or a formal of the enclosing function declared as a byte writer
/// (`out io.Writer`, `buf *bytes.Buffer`, `f *os.File`), passed directly or
/// by address.  Formals are read from the receiver-alias frame, so only the
/// declared type counts, never the name.
fn go_writer_arg_is_non_response(call: Node, code: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(mut writer) = args.named_children(&mut cursor).next() else {
        return false;
    };
    if writer.fkind() == "unary_expression" {
        match writer.child_by_field_name("operand") {
            Some(operand) => writer = operand,
            None => return false,
        }
    }
    let Some(writer_text) = text_of(writer, code) else {
        return false;
    };
    if crate::ssa::type_facts::is_go_non_response_writer(&writer_text) {
        return true;
    }
    let file_handle = crate::ssa::type_facts::TypeKind::FileHandle.label_prefix();
    writer.fkind() == "identifier"
        && crate::labels::receiver_alias_prefix(&writer_text) == file_handle
}

/// `_, ok := m[k]` / `v, ok := m[k]` / `ok := m[k]` where `m` and `k` are
/// bare identifiers.  Type assertions (`x.(T)`), channel receives, multi-value
/// right-hand sides and literal keys return `None`.
fn extract_go_membership_lookup(ast: Node, code: &[u8]) -> Option<MembershipLookup> {
    if !matches!(
        ast.fkind(),
        "short_var_declaration" | "assignment_statement"
    ) {
        return None;
    }
    let index = first_go_expr(ast.child_by_field_name("right")?)?;
    if index.fkind() != "index_expression" {
        return None;
    }
    let base = index.child_by_field_name("operand")?;
    let key = index.child_by_field_name("index")?;
    if base.fkind() != "identifier" {
        return None;
    }
    // The key is a bare identifier or a constant-index element read
    // (`fields[parts[0]]`), which lowering gives a value named `parts[0]`.
    let key_text = if key.fkind() == "identifier" {
        text_of(key, code)?
    } else {
        let reads = go_const_index_reads(key, code);
        match (key.fkind(), reads.as_slice()) {
            ("index_expression", [one]) => one.to_string(),
            _ => return None,
        }
    };
    let left = ast.child_by_field_name("left")?;
    let mut cursor = left.walk();
    let targets: Vec<Node> = left.named_children(&mut cursor).collect();
    if targets.iter().any(|t| t.fkind() != "identifier") {
        return None;
    }
    let named = |n: Node| text_of(n, code).filter(|t| t != "_");
    let (result_var, value_var) = match targets.as_slice() {
        [value, ok] => (named(*ok)?, named(*value)),
        [ok] => (named(*ok)?, None),
        _ => return None,
    };
    Some(MembershipLookup {
        result_var,
        base: text_of(base, code)?,
        key: key_text,
        value_var,
        filled_elsewhere: false,
    })
}

/// First concrete expression inside an `expression_list` (or the node itself
/// when it is already a single expression).  Returns `None` for
/// multi-value RHS lists (`a, b := f()`), where the binding target's type is
/// ambiguous.
fn first_go_expr(n: Node) -> Option<Node> {
    if n.fkind() == "expression_list" {
        let mut cursor = n.walk();
        let exprs: Vec<Node> = n.children(&mut cursor).filter(|c| c.is_named()).collect();
        if exprs.len() == 1 {
            Some(exprs[0])
        } else {
            None
        }
    } else {
        Some(n)
    }
}

/// Read the constructed type's text from a Go constructor expression:
/// `new(T)` → `T`, `&T{}` / `T{}` (composite literals, possibly under a
/// `&` unary) → `T`.  Returns `None` for any other expression shape.
fn go_constructor_type_text(expr: Node, code: &[u8]) -> Option<String> {
    match expr.fkind() {
        "call_expression" => {
            let func = expr.child_by_field_name("function")?;
            if text_of(func, code)?.trim() != "new" {
                return None;
            }
            let args = expr.child_by_field_name("arguments")?;
            let mut cursor = args.walk();
            let first = args.children(&mut cursor).find(|c| c.is_named())?;
            text_of(first, code)
        }
        // `&T{}` — the address-of a composite literal.
        "unary_expression" => {
            let operand = expr.child_by_field_name("operand")?;
            go_constructor_type_text(operand, code)
        }
        // `T{}` composite literal.
        "composite_literal" => {
            let ty = expr.child_by_field_name("type")?;
            text_of(ty, code)
        }
        _ => None,
    }
}

/// Nearest ancestor of `n` that is a call/method-call expression, or `None`
/// when `n` is not nested inside any call.  Used to find the call that
/// *consumes* a value-use identifier (its receiver or argument).
fn nearest_enclosing_call<'a>(n: Node<'a>, lang: &str) -> Option<Node<'a>> {
    let mut cur = n.parent()?;
    loop {
        if matches!(lookup_node(lang, cur), Kind::CallFn | Kind::CallMethod) {
            return Some(cur);
        }
        cur = cur.parent()?;
    }
}

/// Collect value-use identifiers in the sink `ast` whose **every** occurrence
/// is consumed by a numeric- or safe-string-producing call
/// (`x.parse::<u16>()`, `parseInt(x)`, `Atoi(x)`, `Integer.toString(x)`, …).
///
/// Populates [`NodeInfo::numeric_confined_uses`].  Motivated by inline
/// numeric chains flowing into type-suppressible sinks —
/// `Command::arg(s.parse::<u16>().unwrap().to_string())`,
/// `fs::read(format!("/d/{}", s.parse::<u32>()))` — where the inner chain
/// never lowers to its own SSA value, so the value-level
/// [`crate::ssa::type_facts::TypeKind::Int`] suppression cannot reach it; the
/// tainted source leaf is flattened directly into the sink's use set.
///
/// Soundness: an identifier whose count of numeric-confined occurrences is
/// less than its total value-use count (i.e. it also appears raw somewhere in
/// the node) is **not** returned, so a real injection through the same
/// variable still fires.  Bare-callee-name identifiers (`parseInt` in
/// `parseInt(x)`) are excluded from the value-use count.  Gated to Sink nodes;
/// returns empty otherwise.
fn collect_numeric_confined_value_idents(
    ast: Node,
    lang: &str,
    code: &[u8],
    labels: &[DataLabel],
) -> Vec<String> {
    if !labels.iter().any(|l| matches!(l, DataLabel::Sink(_))) {
        return Vec::new();
    }
    // text -> (total value-use occurrences, numeric-confined occurrences)
    let mut counts: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();
    count_confined_idents_into(ast, lang, code, &mut counts);
    let mut idents: Vec<String> = counts
        .into_iter()
        .filter(|(_, (total, conf))| *total > 0 && total == conf)
        .map(|(k, _)| k)
        .collect();
    // Consumers only test membership; sorting keeps the CFG (and the
    // cross-file bodies built from it) the same in every process.
    idents.sort_unstable();
    idents
}

/// Per-identifier numeric-confinement tally for the confinement walk:
/// `text -> (total value-use occurrences, numeric-confined occurrences)`.
type ConfinedCounts = std::collections::HashMap<String, (u32, u32)>;

/// Walk `root` accumulating, per value-use identifier, how many of its
/// occurrences are numeric-confined (consumed by a numeric / safe-string
/// producer) versus its total occurrences.  Factored out of
/// [`collect_numeric_confined_value_idents`] so the Rust `format!`-family
/// handler can re-run the same structured tally on a re-parsed argument
/// subtree and merge into the shared `counts` (preserving the
/// single-raw-occurrence-blocks soundness across the whole sink node).
///
/// Each stack entry carries the node's parent and its nearest enclosing call,
/// so no identifier walks `parent()` (itself O(depth) in tree-sitter), and the
/// confinement verdict of each enclosing call is computed once and shared by
/// every identifier under it.  Callee texts of chained calls can hold whole
/// callback bodies, so recomputing the verdict per identifier made large
/// bundled JS files quadratic.
fn count_confined_idents_into(root: Node, lang: &str, code: &[u8], counts: &mut ConfinedCounts) {
    use crate::ssa::type_facts::{is_int_producing_callee, is_safe_string_producing_callee};
    let lang_enum = crate::symbol::Lang::from_slug(lang);
    let is_call = |n: Node| matches!(lookup_node(lang, n), Kind::CallFn | Kind::CallMethod);
    // Verdict per enclosing call, keyed by `Node::id`.  Ids are unique within
    // one tree; the Rust format-macro path re-parses into a separate tree and
    // recurses with its own map.
    let mut call_confines: HashMap<usize, bool> = HashMap::new();
    let mut stack = vec![(root, root.parent(), nearest_enclosing_call(root, lang))];
    while let Some((n, parent, enclosing_call)) = stack.pop() {
        // Rust `format!`/`write!`/… macros model their arguments as a flat
        // `token_tree` of raw tokens, so the inner `g.parse::<u32>()` chain is
        // NOT a `call_expression` subtree and the enclosing-call tracking
        // below can't see it (the leaf `g` would be counted raw).  Re-parse
        // each interpolated argument expression and tally it structurally,
        // then skip descending into the flat tokens so the phantom
        // method-name tokens (`parse`, `unwrap`) are not miscounted as raw
        // value-uses.
        if lang == "rust"
            && n.fkind() == "macro_invocation"
            && count_rust_format_macro_confined(n, lang, code, counts)
        {
            continue;
        }
        let child_enclosing_call = if is_call(n) { Some(n) } else { enclosing_call };
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push((child, Some(n), child_enclosing_call));
        }
        // Variable references across the supported grammars: `identifier`
        // (Rust/Go/Python/JS/TS/Java/Ruby/C/C++) plus PHP `variable_name`.
        if !matches!(n.fkind(), "identifier" | "variable_name") {
            continue;
        }
        // Skip bare callee-name identifiers (`parseInt` in `parseInt(x)`):
        // they are the `function`/`name` field of a call, not a consumed
        // value.  Method-name identifiers (`.parse`, `.unwrap`) already carry
        // distinct node kinds (`field_identifier` / `property_identifier`) and
        // are excluded by the kind filter above.
        if let Some(p) = parent
            && is_call(p)
        {
            let callee_field = p
                .child_by_field_name("function")
                .or_else(|| p.child_by_field_name("name"));
            if callee_field == Some(n) {
                continue;
            }
        }
        let Some(text) = text_of(n, code) else {
            continue;
        };
        let confined = enclosing_call.is_some_and(|c| {
            *call_confines.entry(c.id()).or_insert_with(|| {
                call_ident_of(c, lang, code).is_some_and(|ci| {
                    is_int_producing_callee(lang_enum, &ci) || is_safe_string_producing_callee(&ci)
                })
            })
        });
        let entry = counts.entry(text).or_insert((0, 0));
        entry.0 += 1;
        if confined {
            entry.1 += 1;
        }
    }
}

/// When `macro_node` is a Rust format-style `macro_invocation`
/// (`format!` / `write!` / `println!` / `panic!` / a `log` severity macro,
/// …), tally numeric-confinement for the value-use identifiers in each of its
/// interpolated argument expressions and merge into `counts`; returns `true`
/// so the caller skips descending into the flat `token_tree`.
///
/// tree-sitter-rust parses a macro's body as an unstructured `token_tree`, so
/// `g.parse::<u32>().unwrap()` inside `fs::read(format!("/d/{}", g.parse::<u32>()
/// .unwrap()))` is a flat token run rather than a `call_expression`.  We split
/// the token_tree into top-level (`,`-separated) argument segments, drop the
/// format-template string literal, and re-parse the remaining segments as Rust
/// expressions so the shared structured tally
/// ([`count_confined_idents_into`]) recovers the receiver→`parse::<u32>()`
/// relationship.  Multi-identifier arguments stay sound: `format!("{}", a +
/// b.parse::<u32>())` confines only `b` (its nearest enclosing call is the
/// numeric `parse`), leaving `a` un-confined.
///
/// Returns `false` for any non-format macro so the caller descends normally
/// (an unrecognised macro's tokens are then counted raw → never confined,
/// the conservative default).  The format-string literal's own constant
/// content is intentionally not vetted: a digits-only interpolation cannot
/// inject `..` / quotes / shell metacharacters, and any constant traversal in
/// the template is developer-authored, not an attacker-controlled taint
/// vector.
fn count_rust_format_macro_confined(
    macro_node: Node,
    lang: &str,
    code: &[u8],
    counts: &mut ConfinedCounts,
) -> bool {
    let Some(name_node) = macro_node.child_by_field_name("macro") else {
        return false;
    };
    let Some(macro_text) = text_of(name_node, code) else {
        return false;
    };
    let leaf = macro_text
        .rsplit("::")
        .next()
        .unwrap_or(macro_text.as_str());
    if !is_rust_format_style_macro(leaf) {
        return false;
    }
    let tt = match macro_node.child_by_field_name("token_tree") {
        Some(t) => t,
        None => {
            let mut cursor = macro_node.walk();
            match macro_node
                .children(&mut cursor)
                .find(|c| c.fkind() == "token_tree")
            {
                Some(t) => t,
                None => return false,
            }
        }
    };
    let segments = split_format_macro_segments(tt);
    if segments.is_empty() {
        // Recognised format macro with no parseable arguments — still claim
        // it so the caller does not re-descend (nothing to confine).
        return true;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return true;
    }
    for seg in segments {
        // Drop the format-template literal segment (`"/data/{}"`): it carries
        // no interpolated value-use and named captures (`{n}`) live in its
        // bytes, not as tokens, so they are deliberately left un-confined.
        if seg.len() == 1 && matches!(seg[0].fkind(), "string_literal" | "raw_string_literal") {
            continue;
        }
        let (Some(first), Some(last)) = (seg.first(), seg.last()) else {
            continue;
        };
        let (start, end) = (first.start_byte(), last.end_byte());
        if start >= end || end > code.len() {
            continue;
        }
        // Re-parse the argument expression in a minimal function/`let` context
        // so tree-sitter-rust yields a structured expression tree, then tally
        // only that expression's value (the synthetic `_nyx_fmt_arg` /
        // wrapper names are never numeric-confined, so they cannot leak into
        // the result).
        let mut wrapped = Vec::with_capacity(end - start + 24);
        wrapped.extend_from_slice(b"fn _nyx_fmt_arg(){let _=");
        wrapped.extend_from_slice(&code[start..end]);
        wrapped.extend_from_slice(b";}");
        let Some(tree) = parser.parse(&wrapped, None) else {
            continue;
        };
        if let Some(value) = format_arg_value_node(tree.root_node()) {
            count_confined_idents_into(value, lang, &wrapped, counts);
        }
    }
    true
}

/// Split a Rust macro `token_tree` into top-level argument segments.  Children
/// alternate between expression tokens and `,` separators; nested
/// parenthesised groups are their own `token_tree` children (so their inner
/// commas are invisible here), while turbofish `::<…>` angle brackets are flat
/// tokens — track angle-bracket depth so a generic `parse::<HashMap<K, V>>`
/// comma does not split an argument.  The surrounding `(`/`)` are dropped.
fn split_format_macro_segments(tt: Node) -> Vec<Vec<Node>> {
    let mut segments: Vec<Vec<Node>> = vec![Vec::new()];
    let mut angle_depth: i32 = 0;
    let mut cursor = tt.walk();
    for child in tt.children(&mut cursor) {
        if !child.is_named() {
            match child.fkind() {
                "(" | ")" => continue,
                "<" => angle_depth += 1,
                ">" => angle_depth = (angle_depth - 1).max(0),
                "," if angle_depth == 0 => {
                    segments.push(Vec::new());
                    continue;
                }
                _ => {}
            }
        }
        segments.last_mut().unwrap().push(child);
    }
    segments.retain(|s| !s.is_empty());
    segments
}

/// Locate the wrapped argument expression inside a re-parsed
/// `fn _nyx_fmt_arg(){let _=<expr>;}` tree: the `value` field of the first
/// `let_declaration`.  Falls back to the whole root (harmless — the synthetic
/// wrapper identifiers are never numeric-confined).
fn format_arg_value_node(root: Node) -> Option<Node> {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.fkind() == "let_declaration"
            && let Some(v) = n.child_by_field_name("value")
        {
            return Some(v);
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

/// Collect the syntactic phantom identifiers a Rust `format!`-family macro
/// flattens into a sink's use set — the macro name plus every method-name
/// token (an `identifier` whose immediately-preceding sibling is `.`) inside
/// its `token_tree`.  These lower to bare-identifier SSA `Param` operands that
/// are not real arguments, so the structural confinement check skips them.
/// See [`NodeInfo::format_macro_method_idents`].
fn collect_format_macro_method_idents(ast: Node, code: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut stack = vec![ast];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
        if n.fkind() != "macro_invocation" {
            continue;
        }
        let Some(name_node) = n.child_by_field_name("macro") else {
            continue;
        };
        let Some(macro_text) = text_of(name_node, code) else {
            continue;
        };
        let leaf = macro_text
            .rsplit("::")
            .next()
            .unwrap_or(macro_text.as_str());
        if !is_rust_format_style_macro(leaf) {
            continue;
        }
        // Macro name token (`format` / `write` / …).
        if let Some(t) = text_of(name_node, code) {
            out.push(t);
        }
        // Method-name tokens: `identifier` preceded by a `.` separator, at any
        // nesting depth within the macro's token_tree.
        let mut inner = vec![n];
        while let Some(m) = inner.pop() {
            let mut c = m.walk();
            let children: Vec<Node> = m.children(&mut c).collect();
            for (i, ch) in children.iter().enumerate() {
                inner.push(*ch);
                if ch.fkind() == "identifier"
                    && i > 0
                    && children[i - 1].fkind() == "."
                    && let Some(t) = text_of(*ch, code)
                {
                    out.push(t);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

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
                c.fkind(),
                "variable_declarator" | "init_declarator" | "let_declaration"
            ) {
                candidate = c
                    .child_by_field_name("value")
                    .or_else(|| c.child_by_field_name("init"));
                if candidate.is_some() {
                    break;
                }
            } else if matches!(lookup_node(lang, c), Kind::Assignment) {
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
    if matches!(lookup_node(lang, rhs), Kind::Function) && rhs.child_count() > 0 {
        return true;
    }
    // Go's `expression_list` wrapping for short_var_declaration's RHS.
    if rhs.fkind() == "expression_list" {
        let mut cursor = rhs.walk();
        for c in rhs.named_children(&mut cursor) {
            let c = unwrap_parens(c);
            if matches!(lookup_node(lang, c), Kind::Function) && c.child_count() > 0 {
                return true;
            }
        }
    }
    false
}

/// Split a read-modify-write assignment whose right-hand side contains a
/// call (`q += fmt(x)`, `$h .= htmlspecialchars($y)`) into two nodes.
/// `call_node` keeps every label the statement classified with and
/// evaluates the right-hand side, but no longer defines or reads the
/// target.  A new unlabelled combine node then computes
/// `q = q <op> <call result>`; SSA lowering takes the call result from the
/// combine node's single predecessor (see [`NodeInfo::rmw_rhs_from_pred`]).
///
/// Kept as one node, the old `q` would sit in the call's implicit argument
/// group: a sink callee would report it as if it were passed in, and a
/// sanitizer callee would clear taint on `q` that the call never touched.
///
/// Logical forms (`x ||= f()`, `x ??= f()`) stay one node: the result is
/// either the old value or the call result, never a combination, and the
/// memoised-acquire idiom (`conn ||= PG::Connection.new(..)`) relies on the
/// call node defining the target for type and resource tracking.
///
/// Returns the node later statements continue from: the combine node when
/// the statement was split, otherwise `call_node`.
fn split_rmw_call(
    g: &mut Cfg,
    call_node: NodeIndex,
    ast: Node,
    lang: &str,
    code: &[u8],
) -> NodeIndex {
    let Some(rmw) = rmw_statement(ast, lang) else {
        return call_node;
    };
    if rmw.is_logical()
        || g[call_node].kind != StmtKind::Call
        || g[call_node].taint.defines.is_none()
        || !rmw.value.is_some_and(|v| subtree_has_call(v, lang))
    {
        return call_node;
    }
    let reads = rmw_target_reads(rmw.target, code);
    if !g[call_node].taint.uses.starts_with(&reads) {
        return call_node;
    }

    let info = &mut g[call_node];
    let target = info.taint.defines.take();
    info.taint.uses.drain(..reads.len());
    info.rmw_assign = false;
    let bin_op = info.bin_op.take();
    info.bin_op_const = None;
    let ast_meta = info.ast.clone();

    let combine = g.add_node(NodeInfo {
        kind: StmtKind::Seq,
        taint: TaintMeta {
            defines: target,
            uses: reads,
            ..Default::default()
        },
        ast: ast_meta,
        bin_op,
        rmw_assign: true,
        rmw_rhs_from_pred: true,
        ..Default::default()
    });
    connect_all(g, &[call_node], combine, EdgeKind::Seq);
    combine
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
    let assign_ast = if matches!(lookup_node(lang, ast), Kind::Assignment) {
        ast
    } else {
        let mut cursor = ast.walk();
        ast.children(&mut cursor)
            .find(|c| matches!(lookup_node(lang, c), Kind::Assignment))?
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
    //
    // A read-modify-write store (`counts[k] += 1`, `cache[k] ??= {}`) is not a
    // pollution channel: with `k == "__proto__"` it reads the existing
    // prototype object and writes back either that object or a primitive
    // (`"[object Object]1"`), and assigning a primitive to `__proto__` is a
    // no-op.  It still lowers to `__index_set__` for the container write.
    let mut pp_labels: smallvec::SmallVec<[DataLabel; 2]> = smallvec::SmallVec::new();
    let mut pp_payload_args: Option<Vec<usize>> = None;
    if matches!(lang, "javascript" | "typescript" | "js" | "ts")
        && rmw_assignment(assign_ast).is_none()
        && !pp_should_suppress_index_set(assign_ast, subscript_node, &arr_text, &idx_text, code)
    {
        pp_labels.push(DataLabel::Sink(Cap::PROTOTYPE_POLLUTION));
        pp_payload_args = Some(vec![0]);
    }

    let map_stores = if lang == "go" {
        go_map_stores(assign_ast, code)
    } else {
        Vec::new()
    };
    let n = g.add_node(NodeInfo {
        map_stores,
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
    while cur.fkind() == "parenthesized_expression" {
        cur = cur.named_child(0)?;
    }
    if cur.fkind() != "binary_expression" {
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
        while left_inner.fkind() == "parenthesized_expression" {
            left_inner = left_inner.named_child(0)?;
        }
        if left_inner.fkind() == "binary_expression" {
            let op_l = left_inner.child_by_field_name("operator")?;
            if text_of(op_l, code).as_deref() == Some("+") {
                leftmost = left_inner;
                continue;
            }
        }
        // `left_inner` is the leftmost atom — must be a string literal
        // whose constant value starts with `redirect:`.
        if !matches!(left_inner.fkind(), "string_literal" | "string") {
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

/// Annotations of a Java declaration as `(leaf name, full annotation text)`.
fn java_declaration_annotations<'a>(decl: Node<'a>, code: &'a [u8]) -> Vec<(&'a str, &'a str)> {
    let mut out = Vec::new();
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        if child.fkind() != "modifiers" {
            continue;
        }
        let mut inner = child.walk();
        for ann in child.children(&mut inner) {
            if !matches!(ann.fkind(), "marker_annotation" | "annotation") {
                continue;
            }
            let Some(name) = ann
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(code).ok())
            else {
                continue;
            };
            let Ok(full) = ann.utf8_text(code) else {
                continue;
            };
            out.push((name.rsplit('.').next().unwrap_or(name).trim(), full));
        }
    }
    out
}

/// True when `ret` sits in a Spring handler method that answers with an HTML
/// body: a mapping annotation whose `produces` names `text/html`, on a
/// `@ResponseBody` method or in a `@RestController` / `@ResponseBody` class,
/// and a `String` return type.  A handler that does not declare an HTML
/// content type returns JSON or plain text, where reflecting input is not
/// cross-site scripting, so it never matches.
fn spring_html_body_handler(ret: Node, code: &[u8]) -> bool {
    const MAPPINGS: &[&str] = &[
        "RequestMapping",
        "GetMapping",
        "PostMapping",
        "PutMapping",
        "DeleteMapping",
        "PatchMapping",
    ];
    let produces_html = |text: &str| {
        text.find("produces").is_some_and(|i| {
            let rest = &text[i..];
            rest.contains("text/html") || rest.contains("TEXT_HTML")
        })
    };
    let mut cur = ret.parent();
    let method = loop {
        let Some(n) = cur else { return false };
        match n.fkind() {
            "method_declaration" => break n,
            // A return inside a lambda or a nested class returns from that
            // body, not from the handler.
            "lambda_expression" | "class_body" | "constructor_declaration" => return false,
            _ => cur = n.parent(),
        }
    };
    if method
        .child_by_field_name("type")
        .and_then(|t| t.utf8_text(code).ok())
        .map(str::trim)
        != Some("String")
    {
        return false;
    }
    let anns = java_declaration_annotations(method, code);
    let mapping = anns.iter().find(|(n, _)| MAPPINGS.contains(n));
    let Some((_, mapping_text)) = mapping else {
        return false;
    };
    let class = method
        .parent()
        .and_then(|b| b.parent())
        .filter(|c| c.fkind() == "class_declaration");
    let class_anns = class
        .map(|c| java_declaration_annotations(c, code))
        .unwrap_or_default();
    let body_response = anns.iter().any(|(n, _)| *n == "ResponseBody")
        || class_anns
            .iter()
            .any(|(n, _)| matches!(*n, "RestController" | "ResponseBody"));
    if !body_response {
        return false;
    }
    produces_html(mapping_text)
        || class_anns
            .iter()
            .any(|(n, t)| *n == "RequestMapping" && produces_html(t))
}

/// Identifiers whose taint reaches the value of a returned HTML string:
/// plain names, `+` concatenation, ternary arms, and value-preserving string
/// methods.  A call to anything else is skipped, since it may be a sanitizer
/// (`escapeHtml4(x)`, `HtmlUtils.htmlEscape(x)`) whose result is clean.
fn collect_html_return_idents<'a>(
    n: Node<'a>,
    code: &[u8],
    out: &mut Vec<String>,
    sources: &mut Vec<Node<'a>>,
) {
    const PASS_THROUGH: &[&str] = &[
        "toString",
        "valueOf",
        "format",
        "formatted",
        "concat",
        "trim",
        "strip",
        "stripLeading",
        "stripTrailing",
        "toLowerCase",
        "toUpperCase",
        "replace",
        "replaceAll",
        "replaceFirst",
        "substring",
        "subSequence",
        "repeat",
        "intern",
    ];
    match n.fkind() {
        "identifier" => {
            if let Ok(t) = n.utf8_text(code) {
                out.push(t.to_string());
            }
        }
        "binary_expression" => {
            for side in ["left", "right"] {
                if let Some(c) = n.child_by_field_name(side) {
                    collect_html_return_idents(c, code, out, sources);
                }
            }
        }
        "parenthesized_expression" => {
            if let Some(c) = n.named_child(0) {
                collect_html_return_idents(c, code, out, sources);
            }
        }
        "ternary_expression" => {
            for arm in ["consequence", "alternative"] {
                if let Some(c) = n.child_by_field_name(arm) {
                    collect_html_return_idents(c, code, out, sources);
                }
            }
        }
        "method_invocation" => {
            let name = n
                .child_by_field_name("name")
                .and_then(|c| c.utf8_text(code).ok());
            if name.is_some_and(|m| !PASS_THROUGH.contains(&m)) {
                // Not a value-preserving method: it may be a sanitizer, so
                // only a call that is itself a source contributes.
                sources.push(n);
            } else if name.is_some() {
                if let Some(obj) = n.child_by_field_name("object") {
                    collect_html_return_idents(obj, code, out, sources);
                }
                if let Some(args) = n.child_by_field_name("arguments") {
                    let mut cursor = args.walk();
                    for a in args.named_children(&mut cursor) {
                        collect_html_return_idents(a, code, out, sources);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Spring `@RestController` / `@ResponseBody` handler that declares
/// `produces = "text/html"` and returns a `String`: the returned string is
/// the response body, so it is an HTML sink (CVE-2024-23819).  Emits a
/// synthetic `__spring_html_body__` Call with `Sink(HTML_ESCAPE)` between
/// `preds` and the Return node.  Returns the new frontier, or `preds`
/// unchanged when the handler does not qualify.
fn try_lower_spring_html_return(
    ast: Node,
    preds: &[NodeIndex],
    g: &mut Cfg,
    lang: &str,
    code: &[u8],
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
) -> Vec<NodeIndex> {
    if lang != "java" || !spring_html_body_handler(ast, code) {
        return preds.to_vec();
    }
    let Some(expr) = ast.named_child(0) else {
        return preds.to_vec();
    };
    let mut uses: Vec<String> = Vec::new();
    let mut candidates: Vec<Node> = Vec::new();
    collect_html_return_idents(expr, code, &mut uses, &mut candidates);
    // A source call in the returned expression (`r.getParameter("q")`) has
    // no variable of its own, so it gets a pre-emitted source node that
    // defines one, which the sink then reads.
    let mut preds: Vec<NodeIndex> = preds.to_vec();
    for (i, call) in candidates.into_iter().enumerate() {
        let Some(args) = call.child_by_field_name("arguments") else {
            continue;
        };
        let Ok(callee) = std::str::from_utf8(&code[call.start_byte()..args.start_byte()]) else {
            continue;
        };
        let callee: String = callee.chars().filter(|c| !c.is_whitespace()).collect();
        let caps = crate::labels::classify_all("java", &callee, None)
            .iter()
            .fold(Cap::empty(), |acc, l| match l {
                DataLabel::Source(bits) => acc | *bits,
                _ => acc,
            });
        if caps.is_empty() {
            continue;
        }
        let synth_name = format!("__nyx_src_{}_ret{}", g.node_count(), i);
        let src_idx = g.add_node(NodeInfo {
            kind: StmtKind::Seq,
            call: CallMeta {
                callee: Some(callee),
                ..Default::default()
            },
            taint: TaintMeta {
                labels: smallvec::smallvec![DataLabel::Source(caps)],
                defines: Some(synth_name.clone()),
                ..Default::default()
            },
            ast: AstMeta {
                span: (call.start_byte(), call.end_byte()),
                enclosing_func: enclosing_func.map(|s| s.to_string()),
            },
            ..Default::default()
        });
        connect_all(g, &preds, src_idx, EdgeKind::Seq);
        preds = vec![src_idx];
        uses.push(synth_name);
    }
    if uses.is_empty() {
        return preds;
    }
    let ord = *call_ordinal;
    *call_ordinal += 1;
    let mut labels: smallvec::SmallVec<[DataLabel; 2]> = smallvec::SmallVec::new();
    labels.push(DataLabel::Sink(Cap::HTML_ESCAPE));
    let n = g.add_node(NodeInfo {
        kind: StmtKind::Call,
        call: CallMeta {
            callee: Some("__spring_html_body__".to_string()),
            arg_uses: vec![uses.clone()],
            call_ordinal: ord,
            sink_payload_args: Some(vec![0]),
            ..Default::default()
        },
        taint: TaintMeta {
            labels,
            uses,
            ..Default::default()
        },
        ast: AstMeta {
            span: (ast.start_byte(), ast.end_byte()),
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        ..Default::default()
    });
    connect_all(g, &preds, n, EdgeKind::Seq);
    vec![n]
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
        if node.fkind() == "jsx_attribute"
            && jsx_attr_name_is(node, "dangerouslySetInnerHTML", code)
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
        if matches!(lookup_node(lang, node), Kind::Function) && node.id() != root.id() {
            continue;
        }
        if node.fkind() == "jsx_expression"
            && let Some(parent) = node.parent()
            && matches!(parent.fkind(), "jsx_element" | "jsx_fragment")
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
    let inner = if value.fkind() == "jsx_expression" {
        let mut cur = value.walk();
        value
            .named_children(&mut cur)
            .find(|c| c.fkind() != "comment")?
    } else {
        value
    };
    let object_kind = inner.fkind();
    if !matches!(
        object_kind,
        "object" | "object_expression" | "object_literal"
    ) {
        return None;
    }
    let mut cur = inner.walk();
    for pair in inner.named_children(&mut cur) {
        if !matches!(
            pair.fkind(),
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
    while cur.fkind() == "parenthesized_expression" {
        let Some(inner) = cur.named_child(0) else {
            return false;
        };
        cur = inner;
    }
    if !matches!(cur.fkind(), "call_expression" | "call") {
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
                if matches!(arg.fkind(), "comment") {
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
    pp_is_guarded_by_proto_check(assign_ast, idx_text, code)
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
    let kind = n.fkind();
    if !matches!(kind, "string" | "string_literal" | "template_string") {
        return None;
    }
    let raw = slice_str(code, n.start_byte(), n.end_byte())?;
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
        match parent.fkind() {
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
            if sibling.fkind() != "if_statement" {
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
    if !matches!(block.fkind(), "statement_block" | "block") {
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
        n.fkind(),
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
    if matches!(stripped.fkind(), "binary_expression") {
        let op = stripped
            .child_by_field_name("operator")
            .map(|o| o.fkind())
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
    while matches!(cur.fkind(), "parenthesized_expression") {
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
    if !matches!(stripped.fkind(), "binary_expression") {
        return None;
    }
    let op = stripped
        .child_by_field_name("operator")
        .map(|o| o.fkind())
        .unwrap_or("");
    if !matches!(op, "===" | "==") {
        return None;
    }
    let left = stripped.child_by_field_name("left")?;
    let right = stripped.child_by_field_name("right")?;
    let left = pp_unwrap_paren(left);
    let right = pp_unwrap_paren(right);
    if let (Some(lv), Some(rs)) = (text_of(left, code), pp_string_literal_value(right, code)) {
        if matches!(left.fkind(), "identifier" | "shorthand_property_identifier") {
            return Some((lv, rs));
        }
    }
    if let (Some(rv), Some(ls)) = (text_of(right, code), pp_string_literal_value(left, code)) {
        if matches!(
            right.fkind(),
            "identifier" | "shorthand_property_identifier"
        ) {
            return Some((rv, ls));
        }
    }
    None
}

/// `is_koa_json_body_assignment` for a statement node that is, or wraps, the
/// assignment.  Only reached after a Sink label was found, so the lookups
/// stay off the common path.
fn is_koa_json_body_node(ast: Node, lang: &str, code: &[u8], label: &DataLabel) -> bool {
    if !matches!(lang, "javascript" | "typescript" | "tsx")
        || !matches!(label, DataLabel::Sink(c) if *c == Cap::HTML_ESCAPE)
    {
        return false;
    }
    let assign = if matches!(lookup_node(lang, ast), Kind::Assignment) {
        Some(ast)
    } else {
        let mut cursor = ast.walk();
        ast.children(&mut cursor)
            .find(|c| matches!(lookup_node(lang, c), Kind::Assignment))
    };
    assign
        .and_then(|a| a.child_by_field_name("left").map(|l| (a, l)))
        .is_some_and(|(a, l)| is_koa_json_body_assignment(a, l, lang, code, label))
}

/// Koa serialises an object or array `ctx.body` as JSON with
/// `Content-Type: application/json`, so assigning a literal of that shape is
/// not a direct XSS sink.  A string, template, identifier or call value keeps
/// the sink because Koa may send it as `text/html`.
fn is_koa_json_body_assignment(
    assign: Node,
    lhs: Node,
    lang: &str,
    code: &[u8],
    label: &DataLabel,
) -> bool {
    if !matches!(lang, "javascript" | "typescript" | "tsx")
        || !matches!(label, DataLabel::Sink(c) if *c == Cap::HTML_ESCAPE)
        || lhs.fkind() != "member_expression"
    {
        return false;
    }
    let Some(rhs) = assign.child_by_field_name("right") else {
        return false;
    };
    if !matches!(rhs.fkind(), "object" | "array") {
        return false;
    }
    // With an HTML content type set in the same function, the body is
    // rendered as markup (an object with a custom `toString` included), so
    // the sink stays.
    member_expr_text(lhs, code).is_some_and(|t| {
        t.eq_ignore_ascii_case("ctx.body") || t.eq_ignore_ascii_case("ctx.response.body")
    }) && !scope_sets_html_content_type(assign, code)
}

/// Label of an assignment target (`el.innerHTML`, `location.href`,
/// `res.headers['X']`).  The full member path is tried first (`location.href`,
/// more specific and avoids false positives on `a.href`), then the property
/// alone (`innerHTML`) for sinks that need no object context, then, for the
/// subscript-set form (`response.headers["X-Foo"] = bar`: Ruby
/// `element_reference`, JS/TS `subscript_expression`, Python `subscript`),
/// the subscript's object path (`response.headers`), so header-injection
/// sinks fire on the bracket form alongside the `set_header` method shapes.
fn classify_assignment_lhs(
    lhs: Node,
    lang: &str,
    code: &[u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<DataLabel> {
    if let Some(full) = member_expr_text(lhs, code)
        && let Some(l) = classify(lang, &full, extra)
    {
        return Some(l);
    }
    if let Some(prop) = lhs.child_by_field_name("property")
        && let Some(prop_text) = text_of(prop, code)
        && let Some(l) = classify(lang, &prop_text, extra)
    {
        return Some(l);
    }
    if matches!(
        lhs.fkind(),
        "subscript_expression" | "subscript" | "element_reference"
    ) {
        let obj = lhs
            .child_by_field_name("object")
            .or_else(|| lhs.child_by_field_name("value"))
            .or_else(|| lhs.child(0));
        if let Some(obj_node) = obj
            && let Some(obj_text) = member_expr_text(obj_node, code)
            && let Some(l) = classify(lang, &obj_text, extra)
        {
            return Some(l);
        }
    }
    None
}

/// JS/TS: pre-emit Source nodes for member-expression sources read on the
/// right-hand side of an assignment whose target is a sink
/// (`el.innerHTML = location.hash`, `location.href = '/' + req.query.next`,
/// `window.location.href = location.hash.substring(1)`).  `push_node` labels
/// such a node with the target's Sink, which leaves no room for a Source on
/// the same node, so without these nodes the sink only saw the untainted
/// `location` / `req` roots.  Returns the effective predecessors and the
/// synthetic names to append to the assignment's uses.
///
/// Arguments of calls on the right-hand side are not searched: a call's own
/// arguments are pre-emitted by [`pre_emit_arg_source_nodes`] when the call
/// is the node's call, and a nested call may be a sanitizer
/// (`DOMPurify.sanitize(location.hash)`).  A call's receiver chain is
/// searched, so `location.hash.substring(1)` counts.
fn pre_emit_sink_assignment_sources(
    g: &mut Cfg,
    ast: Node,
    lang: &str,
    code: &[u8],
    enclosing_func: Option<&str>,
    analysis_rules: Option<&LangAnalysisRules>,
    preds: &[NodeIndex],
) -> (SmallVec<[NodeIndex; 4]>, Vec<String>) {
    let mut effective_preds: SmallVec<[NodeIndex; 4]> = SmallVec::from_slice(preds);
    let mut names: Vec<String> = Vec::new();
    if !matches!(lang, "javascript" | "typescript" | "tsx") {
        return (effective_preds, names);
    }
    let assign = if matches!(lookup_node(lang, ast), Kind::Assignment) {
        Some(ast)
    } else {
        let mut cursor = ast.walk();
        ast.children(&mut cursor)
            .find(|c| matches!(lookup_node(lang, c), Kind::Assignment))
    };
    let Some(assign) = assign else {
        return (effective_preds, names);
    };
    let (Some(lhs), Some(rhs)) = (
        assign.child_by_field_name("left"),
        assign.child_by_field_name("right"),
    ) else {
        return (effective_preds, names);
    };
    let extra = analysis_rules.and_then(|r| {
        if r.extra_labels.is_empty() {
            None
        } else {
            Some(r.extra_labels.as_slice())
        }
    });
    let Some(target_label @ DataLabel::Sink(_)) = classify_assignment_lhs(lhs, lang, code, extra)
    else {
        return (effective_preds, names);
    };
    if is_koa_json_body_assignment(assign, lhs, lang, code, &target_label) {
        return (effective_preds, names);
    }
    let mut found: Vec<(Node, Cap, String)> = Vec::new();
    collect_rhs_member_sources(rhs, lang, code, extra, &mut found);
    for (i, (node, caps, source_text)) in found.into_iter().enumerate() {
        let synth_name = format!("__nyx_src_{}_rhs{}", g.node_count(), i);
        let src_idx = g.add_node(NodeInfo {
            kind: StmtKind::Seq,
            call: CallMeta {
                callee: Some(source_text),
                ..Default::default()
            },
            taint: TaintMeta {
                labels: smallvec::smallvec![DataLabel::Source(caps)],
                defines: Some(synth_name.clone()),
                ..Default::default()
            },
            ast: AstMeta {
                span: (node.start_byte(), node.end_byte()),
                enclosing_func: enclosing_func.map(|s| s.to_string()),
            },
            ..Default::default()
        });
        connect_all(g, &effective_preds, src_idx, EdgeKind::Seq);
        effective_preds.clear();
        effective_preds.push(src_idx);
        names.push(synth_name);
    }
    (effective_preds, names)
}

/// `location` properties that name the page's own origin.
const LOCATION_ORIGIN_PARTS: &[&str] = &["origin", "host", "hostname", "port", "protocol"];

/// True for `location.origin + location.pathname`.  The origin carries the
/// scheme and the full host, and a pathname always starts with `/`, so the
/// host of the resulting URL is fixed and the value cannot navigate off site.
fn is_location_origin_plus_pathname(n: Node, code: &[u8]) -> bool {
    let is_location_part = |node: Node, part: &str| {
        let node = unwrap_parens(node);
        node.fkind() == "member_expression"
            && node
                .child_by_field_name("property")
                .and_then(|p| text_of(p, code))
                .as_deref()
                == Some(part)
            && node.child_by_field_name("object").is_some_and(|o| {
                matches!(
                    member_expr_text(o, code).as_deref(),
                    Some("location" | "window.location" | "document.location" | "self.location")
                )
            })
    };
    let op_is_plus = n
        .child_by_field_name("operator")
        .and_then(|o| text_of(o, code))
        .as_deref()
        == Some("+");
    op_is_plus
        && n.child_by_field_name("left")
            .is_some_and(|l| is_location_part(l, "origin"))
        && n.child_by_field_name("right")
            .is_some_and(|r| is_location_part(r, "pathname"))
}

/// Member reads under `n` that classify as a taint Source by their own
/// path (`location.hash`, `req.body.next` via its `req.body` prefix), with
/// the matched source path.  Does not enter call arguments or function
/// literals; see [`pre_emit_sink_assignment_sources`].
fn collect_rhs_member_sources<'a>(
    n: Node<'a>,
    lang: &str,
    code: &[u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
    out: &mut Vec<(Node<'a>, Cap, String)>,
) {
    match n.fkind() {
        "member_expression" => {
            // `location.origin + location.pathname`: the site's own origin
            // components are not attacker input, and treating the whole
            // `location` object as the Source would flag same-origin
            // navigation.
            if let (Some(obj), Some(prop)) = (
                n.child_by_field_name("object"),
                n.child_by_field_name("property"),
            ) && matches!(
                member_expr_text(obj, code).as_deref(),
                Some("location" | "window.location" | "document.location" | "self.location")
            ) && text_of(prop, code).is_some_and(|p| LOCATION_ORIGIN_PARTS.contains(&p.as_str()))
            {
                return;
            }
            if let Some(full) = member_expr_text_full(n, code) {
                let mut candidate = full.as_str();
                loop {
                    if let Some(DataLabel::Source(caps)) = classify(lang, candidate, extra)
                        && helpers::long_source_path_ok(candidate)
                    {
                        out.push((n, caps, candidate.to_string()));
                        return;
                    }
                    match candidate.rsplit_once('.') {
                        Some((prefix, _)) => candidate = prefix,
                        None => break,
                    }
                }
            }
            if let Some(obj) = n.child_by_field_name("object") {
                collect_rhs_member_sources(obj, lang, code, extra, out);
            }
        }
        "subscript_expression" => {
            if let Some(DataLabel::Source(caps)) = first_member_label(n, lang, code, extra) {
                let text = first_member_text(n, code, true).unwrap_or_default();
                out.push((n, caps, text));
            } else if let Some(obj) = n.child_by_field_name("object") {
                collect_rhs_member_sources(obj, lang, code, extra, out);
            }
        }
        "call_expression" | "new_expression" => {
            if let Some(f) = n
                .child_by_field_name("function")
                .or_else(|| n.child_by_field_name("constructor"))
            {
                collect_rhs_member_sources(f, lang, code, extra, out);
            }
        }
        "arrow_function" | "function_expression" | "function" | "class" => {}
        "binary_expression" if is_location_origin_plus_pathname(n, code) => {}
        _ => {
            let mut cursor = n.walk();
            for child in n.named_children(&mut cursor) {
                collect_rhs_member_sources(child, lang, code, extra, out);
            }
        }
    }
}

/// JS/TS: the gated sink `push_node` rebinds a call node to when its outermost
/// call is unclassified and a call further up the receiver chain is a gated
/// sink (`QueryBuilder.where` under `.getMany()`, `http.get` under `.on(..)`).
/// `None` when the outermost call is not rebound, so [`pre_emit_arg_source_nodes`]
/// and `push_node` agree on which call's arguments the node carries.
fn js_rebound_chain_sink_call<'a>(
    outer: Node<'a>,
    lang: &str,
    code: &[u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<Node<'a>> {
    if !matches!(lang, "javascript" | "typescript" | "tsx") {
        return None;
    }
    let (inner, inner_text) = find_chained_gated_sink_call(outer, lang, code)?;
    if inner.id() == outer.id() || !literals::chain_level_is_gated(lang, &inner_text, inner, code) {
        return None;
    }
    let outer_text = outer
        .child_by_field_name("function")
        .and_then(|f| call_fn_callee_text(f, lang, code))?;
    let outer_text: String = outer_text.chars().filter(|c| !c.is_whitespace()).collect();
    classify_all(lang, &outer_text, extra)
        .is_empty()
        .then_some(inner)
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

    // PHP `echo` / `print` / `<?=` take bare operands instead of an argument
    // list, so a source read straight into them (`echo $_GET['a']`) needs its
    // synthetic Source node here. The names feed the node's `uses` only: the
    // node may also be a call (`echo f($x), $_GET['a']`) whose own argument
    // positions must stay untouched.
    if lang == "php"
        && let Some(construct) = php_output_construct(ast, code)
    {
        let mut found = Vec::new();
        php_direct_operand_sources(construct.operand, code, extra, &mut found);
        for (label, member_text, span) in found {
            let synth_name = format!("__nyx_src_{}_{}", g.node_count(), uses_only.len());
            let mut src_labels: SmallVec<[DataLabel; 2]> = SmallVec::new();
            src_labels.push(label);
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

    let Some(outer_call) = find_call_node(ast, lang) else {
        return (effective_preds, bindings, uses_only);
    };
    // `echo isset($_GET['c']) ? .. : ..`: `isset` / `empty` are not the node's
    // callee (see the callee choice in `push_node`), so their arguments are
    // not sink inputs.
    if lang == "php"
        && php_output_construct(ast, code).is_some()
        && call_node_ident_with_span(outer_call, lang, code)
            .is_some_and(|(name, _)| matches!(name.as_str(), "isset" | "empty"))
    {
        return (effective_preds, bindings, uses_only);
    }
    // A JS/TS method chain whose sink sits in the middle
    // (`repo.createQueryBuilder('u').where(<cond>).getMany()`): `push_node`
    // reads the argument positions from that inner call, so the sources are
    // bound there too.
    let call_ast = js_rebound_chain_sink_call(outer_call, lang, code, extra).unwrap_or(outer_call);
    let Some(args_node) = call_ast.child_by_field_name("arguments") else {
        return (effective_preds, bindings, uses_only);
    };

    // Collect children first (can't borrow cursor across mutable graph ops).
    let children: Vec<_> = {
        let mut cursor = args_node.walk();
        args_node.named_children(&mut cursor).collect()
    };

    // Bail on spread/splat arguments where positional mapping is unreliable.
    // Keyword arguments sit outside the positional numbering (`arg_uses`
    // skips them, see `extract_arg_uses`), so they are skipped rather than
    // bailing: `check_output("ls " + request.args["d"], shell=True)` still
    // binds its positional source.
    for child in &children {
        let k = child.fkind();
        if k == "spread_element"
            || k == "dictionary_splat"
            || k == "list_splat"
            || k == "splat_argument"
            || k == "hash_splat_argument"
        {
            return (effective_preds, bindings, uses_only);
        }
    }
    let children: Vec<_> = children
        .into_iter()
        .filter(|c| !matches!(c.fkind(), "keyword_argument" | "named_argument"))
        .collect();

    let pointer_on = crate::pointer::is_enabled();

    for (pos, child) in children.iter().enumerate() {
        let src_label = first_member_label(*child, lang, code, extra);
        if let Some(DataLabel::Source(caps)) = src_label {
            // Use the *current* node count as a unique token, it equals the
            // index the new Source node will receive.
            let synth_name = format!("__nyx_src_{}_{}", g.node_count(), pos);
            let member_text = first_member_text(*child, code, true);
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
            && is_subscript_kind(child.fkind())
            && let Some((arr_text, idx_text)) = subscript_components(*child, code)
        {
            let synth_name = format!("__nyx_idxget_{}_{}", g.node_count(), pos);
            let span = (child.start_byte(), child.end_byte());

            // A constant-index Go read is also the element value lowering
            // names `arr[idx]`; the synthetic read takes it as its receiver
            // so a check on the element carries to the read's result.
            let elem_reads: Vec<Box<str>> = if lang == "go" {
                const_index_name(&arr_text, &idx_text)
                    .map(|n| vec![n.into_boxed_str()])
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let idx_node = g.add_node(NodeInfo {
                elem_reads,
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
            let k = arg.fkind();
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
                let member_text = first_member_text(arg, code, true);
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
/// Destination-filter placeholder for the synthetic source bound to
/// positional argument `pos`; see [`apply_arg_source_bindings`].
fn arg_source_placeholder(pos: usize) -> String {
    format!("__nyx_argsrc_{pos}")
}

fn apply_arg_source_bindings(
    g: &mut Cfg,
    call_node: NodeIndex,
    bindings: &[(usize, String)],
    uses_only: &[String],
) {
    // Destination filters name the synthetic source of an argument whose
    // destination field reads a member Source through a placeholder: swap in
    // the real binding, and drop placeholders no binding resolved.
    let call = &mut g[call_node].call;
    let resolve = |uses: &mut Option<Vec<String>>, fields: &mut Vec<String>| {
        let Some(list) = uses.as_mut() else {
            return;
        };
        let parallel = fields.len() == list.len();
        let mut i = 0;
        while i < list.len() {
            if !list[i].starts_with("__nyx_argsrc_") {
                i += 1;
                continue;
            }
            match bindings
                .iter()
                .find(|(pos, _)| list[i] == arg_source_placeholder(*pos))
            {
                Some((_, synth)) => {
                    list[i] = synth.clone();
                    i += 1;
                }
                None => {
                    list.remove(i);
                    if parallel {
                        fields.remove(i);
                    }
                }
            }
        }
    };
    resolve(&mut call.destination_uses, &mut Vec::new());
    for f in call.gate_filters.iter_mut() {
        resolve(&mut f.destination_uses, &mut f.destination_fields);
    }
    // A synthetic source feeds the node, so its payload is not all literal
    // even when the node's own call only passes literals
    // (`location.href = location.hash.substring(1)`).
    if !bindings.is_empty() || !uses_only.is_empty() {
        g[call_node].all_args_literal = false;
    }
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

/// Lower a flat chain of `alternative` siblings (Python `elif_clause`s / PHP
/// `else_if_clause`s, optionally trailed by an `else_clause`) into a properly
/// nested else-if CFG.
///
/// tree-sitter exposes these clauses as repeated, FLAT `alternative` fields on
/// a single `if_statement` rather than nesting each `else if` inside the
/// previous `else` (as JS/TS/Rust/Go/Java/C do).  The default single-`else`
/// lowering only consumed the first sibling, silently dropping every 2nd+ elif
/// and the trailing else — so any source/sink/sanitizer/guard living there was
/// invisible to the whole pipeline.  This builder restores the missing CFG
/// nodes by chaining each elif as a guard whose False edge flows into the next
/// alternative.
///
/// `incoming_edge` is the edge label used to enter the chain (the parent `if`'s
/// false edge — `EdgeKind::False` normally, `EdgeKind::True` for Ruby
/// `unless`).  Returns the union of all branch exits plus the final
/// fall-through (when the chain has no terminal `else`).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_alternative_chain<'a>(
    alternatives: &[Node<'a>],
    preds: &[NodeIndex],
    incoming_edge: EdgeKind,
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
    // Predecessor frontier entering the current alternative, and the edge label
    // to use when wiring into it.  Updated as we descend the chain: each elif's
    // False edge becomes the predecessor/edge for the next alternative.
    let mut chain_preds: Vec<NodeIndex> = preds.to_vec();
    let mut chain_edge = incoming_edge;
    let mut exits: Vec<NodeIndex> = Vec::new();

    for &alt in alternatives {
        let is_elif = matches!(alt.fkind(), "elif_clause" | "else_if_clause");

        if is_elif {
            // Guard node for the elif condition.  `push_node` with `StmtKind::If`
            // extracts condition metadata and runs label classification on the
            // clause (its `condition` field), so a source/sink call inside an
            // elif condition is no longer dropped.
            let guard = push_node(
                g,
                StmtKind::If,
                alt,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            connect_all(g, &chain_preds, guard, chain_edge);

            // True branch: the elif body (`consequence` for Python, `body` for
            // PHP / colon-block forms).
            let body = alt
                .child_by_field_name("consequence")
                .or_else(|| alt.child_by_field_name("body"));
            if let Some(b) = body {
                let body_first = NodeIndex::new(g.node_count());
                let body_exits = build_sub(
                    b,
                    &[guard],
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
                if body_first.index() < g.node_count() {
                    connect_all(g, &[guard], body_first, EdgeKind::True);
                    exits.extend(body_exits);
                } else if let Some(&first) = body_exits.first() {
                    connect_all(g, &[guard], first, EdgeKind::True);
                    exits.extend(body_exits);
                } else {
                    // Empty body: the guard's True edge falls through.
                    exits.push(guard);
                }
            } else {
                exits.push(guard);
            }

            // False branch descends to the next alternative.
            chain_preds = vec![guard];
            chain_edge = EdgeKind::False;
        } else {
            // Terminal `else_clause` (or any non-guard block): lower its body and
            // end the chain.  The else body field is `body` for both Python and
            // PHP `else_clause`; fall back to the clause node itself.
            let body = alt.child_by_field_name("body").unwrap_or(alt);
            let body_first = NodeIndex::new(g.node_count());
            let body_exits = build_sub(
                body,
                &chain_preds,
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
            if body_first.index() < g.node_count() {
                connect_all(g, &chain_preds, body_first, chain_edge);
                exits.extend(body_exits);
            } else if let Some(&first) = body_exits.first() {
                connect_all(g, &chain_preds, first, chain_edge);
                exits.extend(body_exits);
            } else {
                exits.extend(chain_preds.iter().copied());
            }
            // An else clause terminates the chain; nothing follows it.
            return exits;
        }
    }

    // Chain ended with an elif (no terminal else): the last guard's False edge
    // is the fall-through path out of the whole if/elif construct.  Materialise
    // it as a synthetic pass-through so the false edge has a concrete target,
    // mirroring the no-else branch in the `Kind::If` arm.
    let pass = g.add_node(NodeInfo {
        kind: StmtKind::Seq,
        ast: AstMeta {
            span: chain_preds
                .first()
                .map(|&n| g[n].ast.span)
                .unwrap_or((0, 0)),
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        ..Default::default()
    });
    connect_all(g, &chain_preds, pass, chain_edge);
    exits.push(pass);
    exits
}

/// Lower a C-style `for` loop's increment/update clause onto the back-edge
/// path.  `back_sources` are the body/continue exits that would otherwise
/// back-edge straight to the loop header.  When an `update_subtree` exists it
/// is lowered from those sources and its exits are returned, so callers
/// back-edge the update's exits to the header instead — making increment-clause
/// side effects (assignments, sanitizer calls) visible to taint analysis.
/// Without an update clause the input sources are returned unchanged, so the
/// CFG is bit-identical to the pre-fix behaviour.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_loop_update<'a>(
    update_subtree: Option<Node<'a>>,
    back_sources: &[NodeIndex],
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
    let Some(update) = update_subtree else {
        return back_sources.to_vec();
    };
    if back_sources.is_empty() {
        return Vec::new();
    }
    let update_exits = build_sub(
        update,
        back_sources,
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
    // If the update produced no CFG nodes (e.g. it was pure trivia), preserve
    // the original back-edge sources so the loop still closes.
    if update_exits.is_empty() {
        back_sources.to_vec()
    } else {
        update_exits
    }
}

/// Emit one `StmtKind::Call` node for `ast` (a call expression, or an
/// expression that contains one), preceded by its pre-emitted argument
/// source nodes, and register any function expressions nested in it as
/// separate bodies.  Returns the call node and whether its callee never
/// returns (the caller decides whether that ends the frontier).
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_call_node<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex],
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
) -> (NodeIndex, bool) {
    let ord = *call_ordinal;
    *call_ordinal += 1;
    let (effective_preds, src_bindings, src_uses_only) =
        pre_emit_arg_source_nodes(g, ast, lang, code, enclosing_func, analysis_rules, preds);
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

    // If the callee never returns, treat as a dead end: no fall-through
    // edge, so a guard whose failing arm aborts stays dominating.  See
    // `is_terminator_call`.
    if let Some(callee) = &g[n].call.callee
        && is_terminator_call(lang, callee, analysis_rules)
    {
        return (n, true);
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

    (n, false)
}

/// True when `ast` is a C++ declaration of an owning smart pointer
/// (`std::unique_ptr<T> p(...)`, `shared_ptr`, `boost::scoped_ptr`,
/// `QScopedPointer`, ...).
fn cpp_decl_is_smart_pointer(ast: Node, code: &[u8]) -> bool {
    if ast.fkind() != "declaration" {
        return false;
    }
    let Some(ty) = ast
        .child_by_field_name("type")
        .and_then(|t| text_of(t, code))
    else {
        return false;
    };
    let base = ty.split('<').next().unwrap_or(&ty);
    let leaf = base
        .rsplit("::")
        .next()
        .unwrap_or(base)
        .trim()
        .to_ascii_lowercase();
    matches!(
        leaf.as_str(),
        "unique_ptr"
            | "shared_ptr"
            | "auto_ptr"
            | "scoped_ptr"
            | "scoped_array"
            | "shared_array"
            | "qscopedpointer"
            | "qsharedpointer"
    )
}

/// See [`CallMeta::ctor_owned_args`].
fn collect_ctor_owned_args(
    ast: Node,
    call_ast: Option<Node>,
    lang: &str,
    code: &[u8],
    is_constructor: bool,
) -> Vec<String> {
    fn java_ctor_args(ctor: Node, code: &[u8], out: &mut Vec<String>, depth: u32) {
        if depth > 8 {
            return;
        }
        let Some(args) = ctor.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            let mut arg = unwrap_parens(arg);
            if arg.fkind() == "cast_expression"
                && let Some(v) = arg.child_by_field_name("value")
            {
                arg = unwrap_parens(v);
            }
            match arg.fkind() {
                "identifier" => {
                    if let Some(t) = text_of(arg, code) {
                        out.push(t);
                    }
                }
                "object_creation_expression" => java_ctor_args(arg, code, out, depth + 1),
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    match lang {
        "java" if is_constructor => {
            let ctor = [Some(ast), call_ast]
                .into_iter()
                .flatten()
                .find(|n| n.fkind() == "object_creation_expression");
            if let Some(ctor) = ctor {
                java_ctor_args(ctor, code, &mut out, 0);
            }
        }
        "cpp" if cpp_decl_is_smart_pointer(ast, code) => {
            let mut cursor = ast.walk();
            for d in ast.children_by_field_name("declarator", &mut cursor) {
                match d.fkind() {
                    // `std::unique_ptr<T> p(raw)` / `p{raw}`
                    "init_declarator" => {
                        if let Some(v) = d.child_by_field_name("value")
                            && matches!(v.fkind(), "argument_list" | "initializer_list")
                        {
                            let mut c = v.walk();
                            for a in v.named_children(&mut c) {
                                let a = unwrap_parens(a);
                                if a.fkind() == "identifier"
                                    && let Some(t) = text_of(a, code)
                                {
                                    out.push(t);
                                }
                            }
                        }
                    }
                    // `std::unique_ptr<T> p(raw);` read as a function
                    // declaration whose single "parameter type" is `raw`.
                    "function_declarator" => {
                        if let Some(params) = d.child_by_field_name("parameters") {
                            let mut c = params.walk();
                            let ps: Vec<Node> = params.named_children(&mut c).collect();
                            if let [p] = ps.as_slice()
                                && p.fkind() == "parameter_declaration"
                                && p.child_by_field_name("declarator").is_none()
                                && let Some(ty) = p.child_by_field_name("type")
                                && ty.fkind() == "type_identifier"
                                && let Some(t) = text_of(ty, code)
                            {
                                out.push(t);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    out
}

/// True when `ast` is (or wraps) an assignment whose target is reached
/// through a pointer or a container element: `*out = v`, `arr[i] = v`,
/// `$a[] = v`, `m[k] = v`.  The defined name is then the pointer or the
/// container, not a fresh local holding the value.
fn assignment_target_is_indirect(ast: Node, lang: &str) -> bool {
    let assign = if lookup_node(lang, ast) == Kind::Assignment {
        Some(ast)
    } else if matches!(lookup_node(lang, ast), Kind::CallWrapper) {
        let mut cursor = ast.walk();
        ast.named_children(&mut cursor)
            .find(|c| lookup_node(lang, c) == Kind::Assignment)
    } else {
        None
    };
    // C / C++ chained store `regs = cfg->priv = xmalloc(n)`: the value also
    // lands in the inner target, which the outer name does not own.
    if matches!(lang, "c" | "cpp") {
        let mut cur = assign;
        while let Some(a) = cur
            && let Some(inner) = a
                .child_by_field_name("right")
                .map(unwrap_parens)
                .filter(|r| lookup_node(lang, r) == Kind::Assignment)
        {
            if let Some(l) = inner.child_by_field_name("left").map(unwrap_parens)
                && matches!(
                    l.fkind(),
                    "field_expression" | "pointer_expression" | "subscript_expression"
                )
            {
                return true;
            }
            cur = Some(inner);
        }
    }
    let Some(lhs) = assign.and_then(|a| a.child_by_field_name("left")) else {
        return false;
    };
    let mut lhs = unwrap_parens(lhs);
    // Go: `left` is an expression_list; only a single target qualifies.
    if lhs.fkind() == "expression_list" {
        let mut cursor = lhs.walk();
        let named: Vec<Node> = lhs.named_children(&mut cursor).collect();
        if named.len() != 1 {
            return false;
        }
        lhs = named[0];
    }
    match lhs.fkind() {
        "pointer_expression" | "unary_expression" => lhs
            .child_by_field_name("operator")
            .is_some_and(|op| op.fkind() == "*"),
        "subscript_expression"
        | "subscript"
        | "index_expression"
        | "array_access"
        | "element_reference" => true,
        // `f(..)->field = v`, `get().field = v`: the object is a call result,
        // so the field lives in storage the call hands out, not in a local.
        "field_expression"
        | "member_expression"
        | "field_access"
        | "selector_expression"
        | "member_access_expression"
        | "attribute" => member_base_is_call(lhs, lang),
        _ => false,
    }
}

/// True when the object a member expression reads from, looking through
/// nested member accesses and parentheses, is a call.
fn member_base_is_call(member: Node, lang: &str) -> bool {
    let mut cur = member;
    for _ in 0..8 {
        let Some(base) = cur
            .child_by_field_name("argument")
            .or_else(|| cur.child_by_field_name("object"))
            .or_else(|| cur.child_by_field_name("operand"))
        else {
            return false;
        };
        let base = unwrap_parens(base);
        if matches!(
            lookup_node(lang, base),
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro
        ) {
            return true;
        }
        cur = base;
    }
    false
}

/// Names a C / C++ / Go / Java function declares itself: parameters
/// (including receivers and named results) and local declarations in any
/// nested scope.  Over-approximate on purpose: a name counted as local here
/// keeps its resource tracking.
fn collect_local_decl_names(n: Node, lang: &str, code: &[u8], out: &mut PendingStores) {
    if out.is_resolved() {
        return;
    }
    fn push_text(n: Node, code: &[u8], out: &mut PendingStores) {
        if let Some(t) = node_str(n, code) {
            out.declare(t);
        }
    }
    fn push_identifiers(n: Node, code: &[u8], out: &mut PendingStores) {
        if n.fkind() == "identifier" {
            push_text(n, code, out);
            return;
        }
        let mut cursor = n.walk();
        for c in n.named_children(&mut cursor) {
            if c.fkind() == "identifier" {
                push_text(c, code, out);
            }
        }
    }
    fn c_declarator_names(mut d: Node, code: &[u8], out: &mut PendingStores) {
        for _ in 0..16 {
            match d.fkind() {
                "identifier" | "field_identifier" => {
                    push_text(d, code, out);
                    return;
                }
                "structured_binding_declarator" => {
                    push_identifiers(d, code, out);
                    return;
                }
                "init_declarator"
                | "pointer_declarator"
                | "array_declarator"
                | "reference_declarator"
                | "attributed_declarator"
                | "function_declarator"
                | "parenthesized_declarator" => {
                    let next = d.child_by_field_name("declarator").or_else(|| {
                        let mut cursor = d.walk();
                        d.named_children(&mut cursor).next()
                    });
                    match next {
                        Some(x) => d = x,
                        None => return,
                    }
                }
                _ => return,
            }
        }
    }

    match (lang, n.fkind()) {
        (
            "c" | "cpp",
            "declaration"
            | "parameter_declaration"
            | "optional_parameter_declaration"
            | "variadic_parameter_declaration"
            | "for_range_loop",
        ) => {
            // A function-scope `static` outlives every call, like a global.
            let mut cursor = n.walk();
            let is_static = n.children(&mut cursor).any(|c| {
                c.fkind() == "storage_class_specifier"
                    && node_str(c, code).is_some_and(|t| t == "static")
            });
            if !is_static {
                let mut cursor = n.walk();
                for d in n.children_by_field_name("declarator", &mut cursor) {
                    c_declarator_names(d, code, out);
                }
            }
        }
        ("go", "short_var_declaration" | "range_clause" | "receive_statement") => {
            if let Some(left) = n.child_by_field_name("left") {
                push_identifiers(left, code, out);
            }
        }
        ("go", "type_switch_statement") => {
            if let Some(alias) = n.child_by_field_name("alias") {
                push_identifiers(alias, code, out);
            }
        }
        (
            "go",
            "var_spec" | "const_spec" | "parameter_declaration" | "variadic_parameter_declaration",
        ) => {
            let mut cursor = n.walk();
            for name in n.children_by_field_name("name", &mut cursor) {
                push_text(name, code, out);
            }
        }
        (
            "java",
            "variable_declarator"
            | "formal_parameter"
            | "catch_formal_parameter"
            | "enhanced_for_statement"
            | "resource",
        ) => {
            if let Some(name) = n.child_by_field_name("name") {
                push_text(name, code, out);
            }
        }
        ("java", "inferred_parameters") => push_identifiers(n, code, out),
        ("java", "lambda_expression") => {
            if let Some(p) = n.child_by_field_name("parameters")
                && p.fkind() == "identifier"
            {
                push_text(p, code, out);
            }
        }
        _ => {}
    }
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        collect_local_decl_names(c, lang, code, out);
    }
}

/// Candidate store targets of a body that no declaration has accounted for
/// yet.  Declarations remove their name; whatever remains is non-local.
struct PendingStores {
    names: HashSet<String>,
}

impl PendingStores {
    fn declare(&mut self, name: &str) {
        self.names.remove(name);
    }

    fn is_resolved(&self) -> bool {
        self.names.is_empty()
    }
}

fn is_js_ts_lang(lang: &str) -> bool {
    matches!(lang, "javascript" | "typescript" | "tsx")
}

/// Collect the names a JS/TS scope binds itself into `out` (see
/// [`BodyMeta::declared_names`]).  `root` is the function node (`is_fn`) or
/// the program root; nested function and class bodies are not entered.
fn collect_js_declared_names(root: Node, code: &[u8], is_fn: bool, out: &mut Vec<String>) {
    fn pattern_names(n: Node, code: &[u8], out: &mut Vec<String>) {
        match n.fkind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                if let Some(t) = node_str(n, code) {
                    out.push(t.to_string());
                }
            }
            "pair_pattern" => {
                if let Some(v) = n.child_by_field_name("value") {
                    pattern_names(v, code, out);
                }
            }
            "assignment_pattern" | "object_assignment_pattern" => {
                if let Some(l) = n.child_by_field_name("left") {
                    pattern_names(l, code, out);
                }
            }
            "object_pattern" | "array_pattern" | "rest_pattern" => {
                let mut cursor = n.walk();
                for c in n.named_children(&mut cursor) {
                    pattern_names(c, code, out);
                }
            }
            _ => {}
        }
    }
    fn walk(n: Node, code: &[u8], out: &mut Vec<String>) {
        match n.fkind() {
            "variable_declarator" => {
                if let Some(name) = n.child_by_field_name("name") {
                    pattern_names(name, code, out);
                }
            }
            "catch_clause" => {
                if let Some(p) = n.child_by_field_name("parameter") {
                    pattern_names(p, code, out);
                }
            }
            "for_in_statement" => {
                // Only a declaring loop (`for (const x of ..)`) binds `x`.
                if n.child_by_field_name("kind").is_some()
                    && let Some(l) = n.child_by_field_name("left")
                {
                    pattern_names(l, code, out);
                }
            }
            "function_declaration" | "generator_function_declaration" | "class_declaration" => {
                if let Some(name) = n.child_by_field_name("name") {
                    pattern_names(name, code, out);
                }
                return;
            }
            "function_expression"
            | "function"
            | "generator_function"
            | "arrow_function"
            | "method_definition"
            | "class"
            | "class_expression" => return,
            _ => {}
        }
        let mut cursor = n.walk();
        for c in n.children(&mut cursor) {
            walk(c, code, out);
        }
    }
    if is_fn {
        let mut cursor = root.walk();
        for c in root.children(&mut cursor) {
            walk(c, code, out);
        }
    } else {
        walk(root, code, out);
    }
}

/// Flag nodes of a C / C++ / Go / Java body that assign a name the function
/// never declares (a global, package variable or unqualified field).  See
/// [`NodeInfo::escaping_store`].
fn mark_nonlocal_defines(g: &mut Cfg, func: Node, lang: &str, code: &[u8], params: &[String]) {
    if matches!(lang, "javascript" | "typescript" | "tsx") {
        mark_param_rooted_member_stores(g, params);
        return;
    }
    if !matches!(lang, "c" | "cpp" | "go" | "java") {
        return;
    }
    let is_candidate = |def: &str| {
        !def.is_empty()
            && !def.starts_with("__")
            && def != "_"
            && def.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    // Only names some node actually stores to need a verdict, so the
    // declaration walk can stop as soon as every one of them is declared.
    let mut pending = PendingStores {
        names: HashSet::new(),
    };
    for idx in g.node_indices() {
        if let Some(def) = g[idx].taint.defines.as_deref()
            && is_candidate(def)
            && !params.iter().any(|p| p == def)
            && !pending.names.contains(def)
        {
            pending.names.insert(def.to_string());
        }
    }
    if pending.is_resolved() {
        return;
    }
    collect_local_decl_names(func, lang, code, &mut pending);
    if pending.is_resolved() {
        return;
    }
    for idx in g.node_indices().collect::<Vec<_>>() {
        let info = &mut g[idx];
        let Some(def) = info.taint.defines.as_deref() else {
            continue;
        };
        if pending.names.contains(def) {
            info.escaping_store = true;
        }
    }
}

/// JS / TS: flag `param.field = v` / `param.a.b = v` stores.  The object
/// belongs to the caller, so a handle stored on it is handed off (Koa
/// `ctx.body = fs.createReadStream(p)`).  `this.field` is not flagged: a
/// class-field acquire is the leak the state checks exist to report.
fn mark_param_rooted_member_stores(g: &mut Cfg, params: &[String]) {
    if params.is_empty() {
        return;
    }
    for idx in g.node_indices().collect::<Vec<_>>() {
        let info = &mut g[idx];
        let Some(def) = info.taint.defines.as_deref() else {
            continue;
        };
        let Some((root, _)) = def.split_once('.') else {
            continue;
        };
        if root != "this" && params.iter().any(|p| p == root) {
            info.escaping_store = true;
        }
    }
}

/// Root identifier of a Go operand: `p`, `p.f`, `p[i]`, `(p)`.
fn go_root_ident<'a>(mut n: Node<'a>, code: &[u8]) -> Option<String> {
    loop {
        match n.fkind() {
            "identifier" => return text_of(n, code),
            "selector_expression" | "index_expression" | "parenthesized_expression" => {
                n = n
                    .child_by_field_name("operand")
                    .or_else(|| n.named_child(0))?;
            }
            _ => return None,
        }
    }
}

/// Whether `func` is a callback whose return value the caller throws away:
/// an argument of `forEach` / `for_each`, or of a Python `map(..)` used as a
/// statement.  A handle such a callback opens never reaches anyone.
fn callback_result_is_discarded(func: Node, code: &[u8]) -> bool {
    let Some(args) = func.parent() else {
        return false;
    };
    if !matches!(args.fkind(), "arguments" | "argument_list") {
        return false;
    }
    let Some(call) = args.parent() else {
        return false;
    };
    let Some(callee) = call
        .child_by_field_name("function")
        .or_else(|| call.child_by_field_name("name"))
    else {
        return false;
    };
    let Ok(text) = callee.utf8_text(code) else {
        return false;
    };
    let leaf = text.rsplit(['.', ':']).next().unwrap_or(text);
    match leaf {
        "forEach" | "for_each" => true,
        "map" if text == "map" => call
            .parent()
            .is_some_and(|p| p.fkind() == "expression_statement"),
        _ => false,
    }
}

/// Node kind ids the alias walk dispatches on, resolved once per walk:
/// comparing `kind_id()` avoids the C-string conversion `kind()` does on
/// every node.
struct GoAliasKinds {
    func_literal: u16,
    unary_expression: u16,
    assignment_statement: u16,
}

fn collect_go_aliased_names(n: Node, in_closure: bool, code: &[u8], out: &mut HashSet<String>) {
    let lang = n.language();
    let kinds = GoAliasKinds {
        func_literal: lang.id_for_node_kind("func_literal", true),
        unary_expression: lang.id_for_node_kind("unary_expression", true),
        assignment_statement: lang.id_for_node_kind("assignment_statement", true),
    };
    collect_go_aliased_names_with(n, in_closure, code, &kinds, out);
}

fn collect_go_aliased_names_with(
    n: Node,
    in_closure: bool,
    code: &[u8],
    kinds: &GoAliasKinds,
    out: &mut HashSet<String>,
) {
    let mut in_closure = in_closure;
    let kind = n.kind_id();
    if kind == kinds.func_literal {
        in_closure = true;
    } else if kind == kinds.unary_expression {
        if n.child_by_field_name("operator")
            .is_some_and(|o| o.fkind() == "&")
            && let Some(operand) = n.child_by_field_name("operand")
            && let Some(name) = go_root_ident(operand, code)
        {
            out.insert(name);
        }
    } else if kind == kinds.assignment_statement
        && in_closure
        && let Some(left) = n.child_by_field_name("left")
    {
        let mut cursor = left.walk();
        for target in left.named_children(&mut cursor) {
            if let Some(name) = go_root_ident(target, code) {
                out.insert(name);
            }
        }
    }
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        collect_go_aliased_names_with(c, in_closure, code, kinds, out);
    }
}

/// Flag Go nodes that define a variable whose address is taken or that a
/// nested function literal assigns.  See [`NodeInfo::aliased_def`].
/// Byte pre-filter for [`mark_aliased_defines`]: whether `body` may take the
/// address of a variable (`&p`, `&p.f`, `&p[i]`).  A unary `&` follows an
/// operator, an opening bracket, a separator or the start of the text, and
/// is followed by a name.  `&&`, `&=`, `&^`, a binary `a & b` and the
/// composite literal `&T{..}` (no variable) do not count.  A superset of what
/// the walk collects is fine; missing one is not.
pub(super) fn go_body_takes_address_of_name(body: &[u8]) -> bool {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0;
    while let Some(off) = body[i..].iter().position(|&b| b == b'&') {
        let at = i + off;
        i = at + 1;
        let next = body.get(at + 1).copied().unwrap_or(b' ');
        if !(next.is_ascii_alphabetic() || next == b'_' || next == b'(') {
            continue;
        }
        let before = body[..at].trim_ascii_end();
        let prev = before.last().copied().unwrap_or(b'(');
        if prev == b'&' || matches!(prev, b')' | b']' | b'}' | b'"' | b'\'' | b'`') {
            continue;
        }
        if is_ident(prev) {
            // `a &b` is a binary and, but after a keyword (`return &x`,
            // `range &xs`) the `&` is unary.
            let word_start = before
                .iter()
                .rposition(|&b| !is_ident(b))
                .map_or(0, |p| p + 1);
            if !matches!(
                &before[word_start..],
                b"return" | b"range" | b"case" | b"go" | b"defer" | b"else"
            ) {
                continue;
            }
        }
        // Skip the operand path; a `{` right after it is a composite literal.
        let mut j = at + 1;
        while j < body.len() && (is_ident(body[j]) || body[j] == b'.') {
            j += 1;
        }
        if body.get(j) == Some(&b'{') {
            continue;
        }
        return true;
    }
    false
}

fn mark_aliased_defines(g: &mut Cfg, func: Node, lang: &str, code: &[u8]) {
    if lang != "go" {
        return;
    }
    // Both shapes leave a byte witness, so most functions skip the walk.
    let body = &code[func.start_byte()..func.end_byte().min(code.len())];
    let has_closure = body
        .windows(5)
        .skip(1)
        .any(|w| w == b"func(" || w == b"func ");
    if !has_closure && !go_body_takes_address_of_name(body) {
        return;
    }
    let mut names = HashSet::new();
    collect_go_aliased_names(func, false, code, &mut names);
    if names.is_empty() {
        return;
    }
    for idx in g.node_indices().collect::<Vec<_>>() {
        let info = &mut g[idx];
        if info
            .taint
            .defines
            .as_deref()
            .is_some_and(|d| names.contains(d))
        {
            info.aliased_def = true;
        }
    }
}

/// Mark the CFG node built from the tail statement of a Ruby method body, or
/// from the expression body of an arrow function / lambda / closure, as the
/// function's implicit return value.  Only a plain value expression
/// qualifies (a variable, a call, a literal container); control flow
/// (`if` / `case` / `begin`), assignments and explicit `return` keep their
/// own semantics.  The node is matched by span so only the node that
/// evaluates the whole statement is marked.
fn mark_implicit_return(g: &mut Cfg, stmt: Node, exits: &[NodeIndex], lang: &str, code: &[u8]) {
    if !matches!(
        lookup_node(lang, stmt),
        Kind::CallFn | Kind::CallMethod | Kind::CallWrapper | Kind::Other
    ) || matches!(
        stmt.fkind(),
        "assignment" | "operator_assignment" | "return" | "comment"
    ) {
        return;
    }
    let span = (stmt.start_byte(), stmt.end_byte());
    let escapes = helpers::collect_value_escapes(stmt, lang, code);
    if escapes.idents.is_empty() && escapes.call_callees.is_empty() {
        return;
    }
    for &idx in exits {
        let info = &mut g[idx];
        if info.ast.span == span && matches!(info.kind, StmtKind::Seq | StmtKind::Call) {
            info.implicit_return = true;
            info.returned_idents = escapes.idents.clone();
            info.returned_call_callees = escapes.call_callees.clone();
        }
    }
}

//    The recursive *work‑horse* that converts an AST node into a CFG slice.
//    Returns the set of *exit* nodes that need to be wired further.
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
    // C / C++ `#if` / `#ifdef` / `#elif` / `#else` groups wrap statements,
    // declarations and whole function definitions.  Lower them as a branch
    // with a merge so their contents are analysed instead of collapsing into
    // one opaque node.
    if matches!(lang, "c" | "cpp")
        && matches!(
            ast.fkind(),
            "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef" | "preproc_else"
        )
    {
        return build_preproc_group(
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
    match lookup_node(lang, ast) {
        //  IF‑/ELSE: two branches that re‑merge afterwards
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
            let cond_subtree = find_condition_subtree(ast, lang);

            let has_short_circuit = cond_subtree
                .map(|c| is_boolean_operator(unwrap_parens(c)).is_some())
                .unwrap_or(false);

            // Check for negation wrapping the entire condition (e.g. `!(a && b)`)
            //, if present, skip short-circuit decomposition (De Morgan out of scope).
            let has_short_circuit = has_short_circuit
                && cond_subtree.map_or(false, |c| {
                    let unwrapped = unwrap_parens(c);
                    !matches!(
                        unwrapped.fkind(),
                        "unary_expression"
                            | "not_operator"
                            | "prefix_unary_expression"
                            | "unary_not"
                            | "unary_op_expression"
                    )
                });

            let is_unless = ast.fkind() == "unless";

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
                    call_ordinal,
                    analysis_rules,
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
            //
            // `alternatives` collects *every* `alternative` field, not just the
            // first.  In tree-sitter-python and tree-sitter-php an
            // `if/elif/.../else` (Python) or `if/elseif/.../else` (PHP) chain
            // produces several FLAT sibling `alternative` fields on one
            // `if_statement` (a list of `elif_clause`/`else_if_clause` nodes
            // optionally trailed by an `else_clause`).  JS/TS/Rust/Go/Java/C
            // nest their `else if`, so they expose at most one `alternative`
            // (the nested if) and the list has length ≤ 1.
            let (then_block, else_block, alternatives) = {
                let field_then = ast
                    .child_by_field_name("consequence")
                    .or_else(|| ast.child_by_field_name("body"));
                let mut alt_cursor = ast.walk();
                let alternatives: Vec<Node> = ast
                    .children_by_field_name("alternative", &mut alt_cursor)
                    .collect();
                let field_else = alternatives.first().copied();

                if field_then.is_some() || field_else.is_some() {
                    (field_then, field_else, alternatives)
                } else {
                    // Fallback: positional block children (Rust `if_expression`)
                    let mut cursor = ast.walk();
                    let blocks: Vec<_> = ast
                        .children(&mut cursor)
                        .filter(|n| lookup_node(lang, n) == Kind::Block)
                        .collect();
                    (blocks.first().copied(), blocks.get(1).copied(), Vec::new())
                }
            };

            // A flat elif/elseif chain has 2+ `alternative` siblings, or a
            // single `alternative` that is itself an elif/else-if clause (the
            // `if a: .. elif b: ..` form with no trailing `else`, where the lone
            // alternative is an `elif_clause` rather than a nested if).  In both
            // cases the default single-`else_block` lowering below would either
            // drop later siblings entirely or fail to treat the elif condition
            // as a branch guard, so route through the dedicated chain builder.
            let is_flat_elif_chain = alternatives.len() > 1
                || alternatives
                    .first()
                    .is_some_and(|a| matches!(a.fkind(), "elif_clause" | "else_if_clause"));

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
            let else_exits = if is_flat_elif_chain {
                // Flat elif/elseif chain: lower every alternative sibling as a
                // proper nested else-if so 2nd+ elif and trailing else clauses
                // are no longer dropped from the CFG.
                build_alternative_chain(
                    &alternatives,
                    else_preds,
                    else_edge,
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
            } else if let Some(b) = else_block {
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
                        ast.fkind(),
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

        //  WHILE / FOR: classic loop with a back edge.
        Kind::While | Kind::For => {
            // C-style `for (init; cond; incr) body` loops (C/C++, JS/TS, Go
            // three-clause, PHP) attach `initializer`/`update` (or `increment`)
            // subtrees that the previous loop lowering ignored entirely — so a
            // taint source bound in the init (`for (cmd = getenv("X"); …)`) or a
            // side effect in the increment had no CFG node at all and was
            // invisible to taint analysis.  Tree-sitter exposes these either as
            // direct fields on the loop node (C/C++/JS/TS/PHP) or nested under a
            // `for_clause` child (Go's three-clause form).  The init runs once
            // before the header; its exits become the header's predecessors so
            // its defs flow into both the condition and the body.
            let clause_owner = ast
                .child_by_field_name("body")
                .is_none()
                .then(|| {
                    let mut c = ast.walk();
                    ast.children(&mut c).find(|n| n.fkind() == "for_clause")
                })
                .flatten();
            let init_subtree = ast
                .child_by_field_name("initializer")
                .or_else(|| ast.child_by_field_name("initialize"))
                .or_else(|| clause_owner.and_then(|fc| fc.child_by_field_name("initializer")));
            let update_subtree = ast
                .child_by_field_name("update")
                .or_else(|| ast.child_by_field_name("increment"))
                .or_else(|| clause_owner.and_then(|fc| fc.child_by_field_name("update")));

            // Lower the initializer (if any) from `preds`; its exits become the
            // header's predecessors.  Empty / absent inits leave `preds`
            // bit-identical to the pre-fix behaviour.
            let init_exits_owned = init_subtree.map(|init| {
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
            let header_preds: &[NodeIndex] = match &init_exits_owned {
                Some(exits) if !exits.is_empty() => exits.as_slice(),
                _ => preds,
            };

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
            connect_all(g, header_preds, header, EdgeKind::Seq);

            // Check for short-circuit condition
            let cond_subtree = ast.child_by_field_name("condition");
            let has_short_circuit = cond_subtree
                .map(|c| {
                    let unwrapped = unwrap_parens(c);
                    is_boolean_operator(unwrapped).is_some()
                        && !matches!(
                            unwrapped.fkind(),
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
                    .find(|n| lookup_node(lang, n) == Kind::Block)
            }) {
                Some(b) => b,
                None => {
                    warn!(
                        "loop without body (error recovery?): kind={} byte={}",
                        ast.fkind(),
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
                    call_ordinal,
                    analysis_rules,
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

                // The increment runs at the end of each iteration before the
                // condition is re-checked, so it sits on the back-edge path
                // between the body/continue exits and the header.
                let mut back_sources: Vec<NodeIndex> = body_exits;
                back_sources.extend(loop_continues.iter().copied());
                let back_sources = lower_loop_update(
                    update_subtree,
                    &back_sources,
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
                // Back-edges go to header (not into the condition chain)
                for &e in &back_sources {
                    connect_all(g, &[e], header, EdgeKind::Back);
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

                // The increment runs on the back-edge path (end of each
                // iteration, before the next condition check).
                let mut back_sources: Vec<NodeIndex> = body_exits;
                back_sources.extend(loop_continues.iter().copied());
                let back_sources = lower_loop_update(
                    update_subtree,
                    &back_sources,
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
                // Back‑edge for every linear exit → header.
                for &e in &back_sources {
                    connect_all(g, &[e], header, EdgeKind::Back);
                }
                // Falling out of the loop = header’s false branch +
                // any break targets that exit the loop.
                let mut exits = vec![header];
                exits.extend(loop_breaks);
                exits
            }
        }

        //  Control-flow sinks (return / break / continue).
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
                let post_jsx = try_lower_spring_html_return(
                    ast,
                    &post_jsx,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
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
                effective_preds = try_lower_spring_html_return(
                    ast,
                    &effective_preds,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
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

        //  BLOCK: statements execute sequentially
        Kind::SourceFile | Kind::Block => {
            // Ruby body_statement with rescue/ensure = implicit begin/rescue
            if lang == "ruby" && ast.fkind() == "body_statement" {
                let mut check = ast.walk();
                if ast
                    .children(&mut check)
                    .any(|c| c.fkind() == "rescue" || c.fkind() == "ensure")
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

            // Ruby methods return the value of their last statement.  Note it
            // so the resource passes can see `def open_log(p) File.open(p) end`
            // and `f = File.open(p); f` hand the handle to the caller.
            let ruby_tail_stmt = if lang == "ruby"
                && ast.fkind() == "body_statement"
                && ast
                    .parent()
                    .is_some_and(|p| matches!(p.fkind(), "method" | "singleton_method"))
            {
                let mut c = ast.walk();
                ast.named_children(&mut c)
                    .filter(|n| n.fkind() != "comment")
                    .last()
                    .map(|n| n.id())
            } else {
                None
            };

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
                let is_defer = lang == "go" && child.fkind() == "defer_statement";
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

                if ruby_tail_stmt == Some(child.id()) {
                    mark_implicit_return(g, child, &child_exits, lang, code);
                }

                let is_preproc = child.fkind().starts_with("preproc_");
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
            // A function declared in a `finally` clause lowered a second time
            // for the early-exit paths: the first copy registered its body.
            if in_duplicate_finally_copy() {
                let placeholder = g.add_node(make_empty_node_info(
                    StmtKind::Seq,
                    (ast.start_byte(), ast.end_byte()),
                    enclosing_func,
                ));
                connect_all(g, preds, placeholder, EdgeKind::Seq);
                return vec![placeholder];
            }

            // ── 1) Extract function name ──────────────────────────────────────
            // Lambda expressions don't have meaningful names; force the
            // synthetic anon name to avoid C++ lambdas picking up parameter
            // names via "declarator".
            let fn_name = if ast.fkind() == "lambda_expression" {
                anon_fn_name(ast.start_byte())
            } else {
                ast.child_by_field_name("name")
                    .or_else(|| {
                        params::c_function_declarator(ast)
                            .and_then(|d| d.child_by_field_name("declarator"))
                    })
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
                compute_container_and_kind(ast, ast.fkind(), &fn_name, code);
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
                    .find(|n| matches!(lookup_node(lang, n), Kind::Block | Kind::SourceFile))
            }) {
                Some(b) => b,
                None => {
                    warn!(
                        "fn without body (forward decl / abstract / error recovery): kind={} name=’{}’",
                        ast.fkind(),
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

            // Go typed formals (`req *http.Request`, `ctx *gin.Context`,
            // `w http.ResponseWriter`, `c *http.Client`) classify under their
            // canonical receiver prefix while this body (and any closure
            // nested in it) is built.
            //
            // Rust `conn: &Connection` formals take the `DatabaseConnection`
            // prefix the same way.
            let receiver_aliases = match lang {
                "go" => Some(crate::labels::push_receiver_aliases(
                    params::go_receiver_alias_frame(ast, code),
                )),
                "rust" => Some(crate::labels::push_receiver_aliases(
                    params::rust_receiver_alias_frame(ast, code),
                )),
                _ => None,
            };

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
            drop(receiver_aliases);

            // An expression body (`() => fs.createReadStream(p)`,
            // `lambda: open(p)`) is the function's return value.
            if matches!(
                lang,
                "javascript" | "typescript" | "tsx" | "python" | "rust"
            ) && lookup_node(lang, body_ast) != Kind::Block
                && !callback_result_is_discarded(ast, code)
            {
                mark_implicit_return(&mut fn_graph, body_ast, &body_exits, lang, code);
            }

            // ── 3) Wire exits to Exit node ────────────────────────────────────
            for &b in &body_exits {
                connect_all(&mut fn_graph, &[b], fn_exit, EdgeKind::Seq);
            }
            // Wire internal Return/Throw nodes to Exit (both terminate this
            // body).  A return that runs a `finally` clause first reaches
            // Exit through that clause's tail instead.
            for idx in fn_graph.node_indices().collect::<Vec<_>>() {
                if matches!(fn_graph[idx].kind, StmtKind::Return | StmtKind::Throw)
                    && idx != fn_exit
                    && !fn_graph[idx].finally_return
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
                    let site = build_callee_site(callee, info, lang, code);
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
            let key = FuncKey::from_parts(
                Lang::from_slug(lang).unwrap_or(Lang::Rust),
                file_path.to_owned(),
                fn_container.clone(),
                fn_name.clone(),
                Some(param_count),
                fn_disambig,
                fn_kind,
            );
            let body_func_key = key.clone();
            summaries.insert(
                key,
                LocalFuncSummary {
                    entry: fn_entry,
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

            // ── 5b) Flag assignments to names this body never declares ───────
            mark_nonlocal_defines(&mut fn_graph, ast, lang, code, &param_names);
            mark_aliased_defines(&mut fn_graph, ast, lang, code);

            // ── 6) Push BodyCfg ───────────────────────────────────────────────
            let declared_names = if is_js_ts_lang(lang) {
                let mut names = param_names.clone();
                for fields in &param_destructured_fields {
                    names.extend(fields.iter().cloned());
                }
                collect_js_declared_names(ast, code, true, &mut names);
                names.sort_unstable();
                names.dedup();
                names
            } else {
                Vec::new()
            };
            let auth_decorators = extract_auth_decorators(ast, lang, code);
            let route_captures = extract_route_path_captures(ast, lang, code);
            let param_route_capture: Vec<bool> = if lang == "java" {
                params::java_request_bound_flags(ast, code, param_names.len())
            } else if route_captures.is_empty() {
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
                    declared_names,
                },
                graph: fn_graph,
                entry: fn_entry,
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
            //
            // A statement-level Rust `match`, bare `{ .. }` block or
            // `unsafe { .. }` block is wrapped the same way.  Collapsing it
            // into one node would hide every source, sink and definition in
            // its arms or body, so walk it instead.  Only the statement
            // wrapper qualifies: `let x = match ..` and `let v = unsafe { .. }`
            // keep their single-node lowering (the let binding and
            // `detect_rust_let_match_guard` depend on it), and `async` /
            // `const` blocks stay collapsed because their bodies do not run
            // in place.  Known limit, shared with `if` bodies: SSA is keyed
            // by name, so a `let x` inside the block that shadows an outer
            // `x` also replaces it for the code after the block.
            let rust_stmt_block = lang == "rust" && ast.fkind() == "expression_statement";
            if let Some(inner) = ast.children(&mut cursor).find(|c| {
                matches!(
                    lookup_node(lang, c),
                    Kind::InfiniteLoop
                        | Kind::While
                        | Kind::For
                        | Kind::If
                        | Kind::Return
                        | Kind::Throw
                        | Kind::Break
                        | Kind::Continue
                ) || (rust_stmt_block
                    && matches!(c.fkind(), "match_expression" | "block" | "unsafe_block"))
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

            // Ternary-RHS split: `var x = c ? a : b;`, `obj.prop = c ? a : b;`,
            // Python `x = a if c else b`, PHP `$x = c ? a : b;` lower to a
            // real diamond CFG so the condition is control-flow (not a
            // data-flow `uses` entry) and an allowlist test in it guards the
            // arm it selects.  Routing Java through the diamond also lets
            // `fold_constant_branches` prune dead constant-condition arms
            // (`cond ? "const" : param`) the same way it does for the if-form.
            if ternary_split_lang(lang)
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
            let (effective_preds, src_bindings, mut src_uses_only) = if kind == StmtKind::Call
                || (lang == "php" && php_output_construct(ast, code).is_some())
            {
                pre_emit_arg_source_nodes(g, ast, lang, code, enclosing_func, analysis_rules, preds)
            } else {
                (SmallVec::from_slice(preds), Vec::new(), Vec::new())
            };
            let (effective_preds, rhs_sources) = pre_emit_sink_assignment_sources(
                g,
                ast,
                lang,
                code,
                enclosing_func,
                analysis_rules,
                &effective_preds,
            );
            src_uses_only.extend(rhs_sources);

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
            if ast.fkind() == "with_item"
                && g[node].kind == StmtKind::Call
                && g[node].taint.defines.is_some()
            {
                g[node].managed_resource = true;
            }

            connect_all(g, &effective_preds, node, EdgeKind::Seq);

            // If the callee never returns, treat as a dead end: no
            // fall-through edge, so a guard whose failing arm aborts stays
            // dominating.  See `is_terminator_call`.
            let never_returns = kind == StmtKind::Call
                && g[node]
                    .call
                    .callee
                    .as_deref()
                    .is_some_and(|callee| is_terminator_call(lang, callee, analysis_rules));

            // `q += fmt(x)`: evaluate the call, then combine with the old `q`.
            let tail = if never_returns {
                node
            } else {
                split_rmw_call(g, node, ast, lang, code)
            };

            // React JSX `dangerouslySetInnerHTML={{__html: x}}` synthesis
            // (Phase 06): chained after the wrapper Call/Seq for cases like
            // `<div .../>;` (expression_statement) where the JSX appears as
            // a top-level expression statement.  No-op when the wrapper has
            // no matching JSX descendant.
            let post_jsx_frontier = try_lower_jsx_dangerous_html(
                ast,
                &[tail],
                g,
                lang,
                code,
                enclosing_func,
                call_ordinal,
                analysis_rules,
            );

            if never_returns {
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
                && let Some((guard, let_name, alternatives_diverge)) =
                    detect_rust_let_match_guard(ast, code)
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
                // When every other arm diverges (`_ => return`,
                // `_ => panic!(…)`), the guard-false path never reaches the
                // code after the `let`: the binding only exists on the
                // guarded arm.  Leaving the false gate on the frontier would
                // hand the join an unvalidated predecessor, and
                // `validated_must` (AND-on-join) would drop the guard's
                // narrowing, reporting a value the guard already proved safe.
                // The false gate stays in the graph as a dead end, the same
                // CFG shape an explicit `return` arm produces.
                if alternatives_diverge {
                    return vec![true_gate];
                }
                return vec![true_gate, false_gate];
            }

            post_jsx_frontier
        }

        // Direct call nodes (Ruby `call`, Python `call`, etc. when they appear
        // as direct children of a block rather than wrapped in expression_statement)
        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
            let (n, never_returns) = emit_call_node(
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
            if never_returns {
                return Vec::new();
            }
            vec![n]
        }

        // Assignment that may contain a call (Python `x = os.getenv(...)`, Ruby `x = gets()`)
        Kind::Assignment => {
            // Ternary-RHS split, same rationale as the CallWrapper branch
            // (Ruby `x = c ? a : b` is a bare `assignment` statement).  Not for
            // `x += c ? a : b`, which reads `x`.
            if ternary_split_lang(lang)
                && rmw_assignment(ast).is_none()
                && let (Some(left), Some(right)) = (
                    ast.child_by_field_name("left"),
                    ast.child_by_field_name("right"),
                )
            {
                let rhs = unwrap_parens(right);
                if ternary_parts(rhs).is_some() {
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
            let (effective_preds, rhs_sources) = pre_emit_sink_assignment_sources(
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
                kind,
                ast,
                lang,
                code,
                enclosing_func,
                ord,
                analysis_rules,
            );
            apply_arg_source_bindings(g, n, &[], &rhs_sources);
            connect_all(g, &effective_preds, n, EdgeKind::Seq);
            // `q += fmt(x)`: evaluate the call, then combine with the old `q`.
            let n = split_rmw_call(g, n, ast, lang, code);
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

        //  Every other node = simple sequential statement
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

/// Lower one C / C++ preprocessor conditional group.
///
/// The group body runs sequentially from `preds`.  The `alternative` chain
/// (`#elif` / `#else`) is an independent path from the same `preds`.  Without
/// an `#else` the body may also be skipped, so `preds` is an exit too.  Exits
/// are the union, so a definition in one arm never kills one from another.
#[allow(clippy::too_many_arguments)]
fn build_preproc_group<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex],
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
    let condition = ast.child_by_field_name("condition");
    let name = ast.child_by_field_name("name");
    let alternative = ast.child_by_field_name("alternative");
    let mut frontier = preds.to_vec();
    let mut cursor = ast.walk();
    for child in ast.named_children(&mut cursor) {
        let is_header = [condition, name, alternative]
            .into_iter()
            .flatten()
            .any(|n| n.id() == child.id());
        if is_header {
            continue;
        }
        frontier = build_sub(
            child,
            &frontier,
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
    let mut exits = frontier;
    match alternative {
        Some(alt) => exits.extend(build_sub(
            alt,
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
        )),
        // `#else` is itself the last alternative; every other group can be
        // skipped entirely.
        None if ast.fkind() != "preproc_else" => exits.extend_from_slice(preds),
        None => {}
    }
    let mut seen = std::collections::HashSet::new();
    exits.retain(|n| seen.insert(*n));
    exits
}

/// Languages whose `x = cond ? a : b` assignments lower to a CFG diamond
/// (see `conditions::build_ternary_diamond`).
fn ternary_split_lang(lang: &str) -> bool {
    matches!(
        lang,
        "javascript" | "typescript" | "tsx" | "java" | "python" | "ruby" | "php"
    )
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
    // Node kinds and their classes for this file's grammar, read by
    // `fkind()` / `lookup_node()` until the scope drops at the end.
    let _kind_table = fast_kind::install(&tree.language(), lang);

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
    // bind the local names of `from flask import abort` (and friends) so
    // the builder dead-ends those calls like `sys.exit`.
    if lang == "python" {
        PYTHON_NORETURN_IMPORTS.with(|cell| {
            *cell.borrow_mut() = collect_python_noreturn_imports(tree.root_node(), code);
        });
    }
    literals::clear_ruby_scope_bindings();
    if lang == "rust" {
        rust_receivers::populate(tree, code);
    }
    // Receiver-alias frames are scoped to function bodies by guards in
    // `build_sub`; start from an empty stack regardless.
    crate::labels::clear_receiver_aliases();
    params::clear_go_struct_typed_fields();

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
    // Python: the file's `from M import n` bindings, consulted by label
    // classification while the nodes are built and kept on the `FileCfg` for
    // the taint passes (see `extract_python_import_paths`).
    let python_imports = if lang == "python" {
        extract_python_import_paths(tree, code)
    } else {
        HashMap::new()
    };
    let mut build_top_level = || {
        build_sub(
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
        )
    };
    // JS/TS call-shape rules (tagged SQL templates) read the import view
    // while the CFG is built, the same way Python's do.
    let js_imports = if matches!(lang, "javascript" | "typescript" | "tsx") {
        extract_local_import_view(tree, code)
    } else {
        HashMap::new()
    };
    let exits = if !python_imports.is_empty() {
        crate::ssa::type_facts::with_file_imports(Some(&python_imports), build_top_level)
    } else if !js_imports.is_empty() {
        crate::ssa::type_facts::with_file_imports(Some(&js_imports), build_top_level)
    } else {
        build_top_level()
    };
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
    let top_declared_names = if is_js_ts_lang(lang) {
        let mut names = Vec::new();
        collect_js_declared_names(tree.root_node(), code, false, &mut names);
        names.sort_unstable();
        names.dedup();
        names
    } else {
        Vec::new()
    };
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
            declared_names: top_declared_names,
        },
        graph: g,
        entry,
    };
    bodies.insert(0, toplevel);
    // Sort by BodyId so that bodies[i].meta.id == BodyId(i).
    // Nested functions are pushed before their parents during build_sub,
    // so the Vec may be out of order before this sort.
    bodies.sort_by_key(|b| b.meta.id);

    // Leading identifiers of URL-building strings (`API + id`) resolve against
    // the file's module-level string constants, now that every body exists.
    module_consts::resolve_prefix_idents(&mut bodies);
    module_consts::resolve_root_idents(&mut bodies, lang, code);

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

    if lang == "ruby" {
        keyword_args::reorder_keyword_args(&mut bodies, &summaries);
    }

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
            apply_gated_label_rules(&mut bodies, lang, extra, &local_imports, tree, code);
        }
        local_imports
    } else {
        // Empty for every language but Python, whose view holds dotted paths.
        python_imports
    };

    retain_sound_const_collections(&mut bodies, tree.root_node(), lang, code);
    if lang == "go" {
        mark_shared_map_lookups(&mut bodies);
        mark_unstable_elem_bases(&mut bodies, tree.root_node(), code);
    }

    // Clear the per-file DFS-index map so it does not leak to the next
    // file built on this thread.
    clear_fn_dfs_indices();
    // same hygiene for the DTO map.
    DTO_CLASSES.with(|cell| cell.borrow_mut().clear());
    TYPE_ALIAS_LC.with(|cell| cell.borrow_mut().clear());
    LOCAL_RECEIVER_TYPES.with(|cell| cell.borrow_mut().clear());
    PYTHON_NORETURN_IMPORTS.with(|cell| cell.borrow_mut().clear());
    literals::clear_ruby_scope_bindings();
    rust_receivers::clear();
    crate::labels::clear_receiver_aliases();
    params::clear_go_struct_typed_fields();

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

/// Set [`MembershipLookup::filled_elsewhere`] on every lookup of a map its own
/// body does not define when a different body stores a non-literal key into a
/// map of that name that body does not define either.  Runs once per Go file
/// and only when both a lookup and such a store exist.
fn mark_shared_map_lookups(bodies: &mut [BodyCfg]) {
    let defines = |b: &BodyCfg, name: &str| {
        b.graph.node_weights().any(|n| {
            n.taint.defines.as_deref() == Some(name)
                || n.taint.extra_defines.iter().any(|d| d == name)
        })
    };
    // (body index, map name) for every store with a non-literal key into a
    // map the storing body does not define.
    let mut stores: Vec<(usize, String)> = Vec::new();
    for (i, b) in bodies.iter().enumerate() {
        for n in b.graph.node_weights() {
            for ms in &n.map_stores {
                if !ms.key_idents.is_empty()
                    && !defines(b, &ms.base)
                    && !stores.iter().any(|(j, m)| *j == i && *m == ms.base)
                {
                    stores.push((i, ms.base.clone()));
                }
            }
        }
    }
    if stores.is_empty() {
        return;
    }
    let mut marks: Vec<(usize, petgraph::graph::NodeIndex)> = Vec::new();
    for (i, b) in bodies.iter().enumerate() {
        for idx in b.graph.node_indices() {
            let Some(l) = b.graph[idx].membership_lookup.as_ref() else {
                continue;
            };
            if stores.iter().any(|(j, m)| *j != i && *m == l.base) && !defines(b, &l.base) {
                marks.push((i, idx));
            }
        }
    }
    for (i, idx) in marks {
        if let Some(l) = bodies[i].graph[idx].membership_lookup.as_mut() {
            l.filled_elsewhere = true;
        }
    }
}

/// Keep `TaintMeta::const_collection` only on file-scope collections that
/// nothing else in the file can reach.
///
/// A literal collection is constant for a loop over it only while it is never
/// mutated, aliased or handed to other code.  Every identifier in the file
/// spelled like the collection must be its own declaration or the iterable of
/// a `for ... of/in` loop; any other mention (a `.push` call, an argument, an
/// export, a shadowing declaration) clears the flag.  The scan runs once per
/// file and only when a flagged collection exists.
fn retain_sound_const_collections(bodies: &mut [BodyCfg], root: Node, lang: &str, code: &[u8]) {
    if !matches!(lang, "javascript" | "typescript" | "tsx" | "python") {
        for body in bodies.iter_mut() {
            for info in body.graph.node_weights_mut() {
                info.taint.const_collection = false;
            }
        }
        return;
    }
    let mut names: HashSet<String> = HashSet::new();
    for body in bodies.iter() {
        for info in body.graph.node_weights() {
            if info.taint.const_collection
                && let Some(d) = info.taint.defines.as_deref()
            {
                names.insert(d.to_string());
            }
        }
    }
    if names.is_empty() {
        return;
    }
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
        if n.child_count() != 0 || !(n.fkind().ends_with("identifier") || n.fkind() == "constant") {
            continue;
        }
        let Some(text) = text_of(n, code) else {
            continue;
        };
        if !names.contains(&text) {
            continue;
        }
        let allowed = n.parent().is_some_and(|p| {
            let field_is = |f: &str| p.child_by_field_name(f).map(|c| c.id()) == Some(n.id());
            match p.fkind() {
                // `const NAMES = [..]`.  An exported declaration is
                // importable, and another module may mutate it.
                "variable_declarator" => {
                    field_is("name")
                        && !p
                            .parent()
                            .and_then(|d| d.parent())
                            .is_some_and(|e| e.fkind() == "export_statement")
                }
                // `NAMES = [..]` (Python).  A public module-level list can be
                // mutated by any importer; only private names and immutable
                // tuples are provably constant.
                "assignment" => {
                    field_is("left")
                        && (text.starts_with('_')
                            || p.child_by_field_name("right")
                                .is_some_and(|r| r.fkind() == "tuple"))
                }
                // `for (const x of NAMES)` / `for x in NAMES:`
                "for_in_statement" | "for_statement" => field_is("right"),
                _ => false,
            }
        });
        if !allowed {
            names.remove(&text);
            if names.is_empty() {
                break;
            }
        }
    }
    for body in bodies.iter_mut() {
        for info in body.graph.node_weights_mut() {
            if info.taint.const_collection
                && !info
                    .taint
                    .defines
                    .as_deref()
                    .is_some_and(|d| names.contains(d))
            {
                info.taint.const_collection = false;
            }
        }
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
            // A promisify alias must inherit not just the wrapped callee's
            // sink *label* but also its arg-position restriction.
            // `promisify(execFile)` is a `SHELL_ESCAPE` sink whose only
            // injectable payload is arg 0 (the binary), exactly like the bare
            // `=execFile` gate (`payload_args: &[0]`).  Without carrying the
            // gate's `payload_args`, the alias call was treated as an
            // unrestricted flat sink, so taint reaching the args array /
            // options object at arg 1+ spuriously fired — e.g. OneUptime
            // CVE-2026-27728's patched form `execFileAsync(cmd, [.., dest])`,
            // where `execFile` no longer spawns a shell and the destination is
            // a non-injectable argv element.  Union the wrapped gate's
            // concrete payload positions; bail (leave unrestricted) if any
            // matching gate declares `ALL_ARGS_PAYLOAD`.
            let mut wrapped_payload: Vec<usize> = Vec::new();
            let mut wrapped_has_restricted_sink = false;
            let mut wrapped_all_args_sink = false;
            // Gate-match the wrapped callee AND its bare leaf name.  The
            // exec-family gates use the `=` exact-only sigil (to avoid
            // `container.exec` collisions at classification time), so
            // `promisify(child_process.execFile)` — whose wrapped callee is the
            // qualified `child_process.execFile` — would otherwise miss the
            // `=execFile` gate.  A payload restriction only ever narrows which
            // args are taint-checked (it never adds findings), so applying the
            // leaf's gate is strictly safe-directional.
            let leaf = alias
                .wrapped
                .rsplit(['.', ':'])
                .next()
                .unwrap_or(alias.wrapped.as_str());
            let mut gate_targets: Vec<&str> = vec![alias.wrapped.as_str()];
            if leaf != alias.wrapped.as_str() {
                gate_targets.push(leaf);
            }
            for target in gate_targets {
                for gm in classify_gated_sink(lang, target, |_| None, |_| None, |_| false).iter() {
                    if !wrapped_labels.contains(&gm.label) {
                        wrapped_labels.push(gm.label);
                    }
                    if matches!(gm.label, crate::labels::DataLabel::Sink(_)) {
                        if gm.payload_args == crate::labels::ALL_ARGS_PAYLOAD {
                            wrapped_all_args_sink = true;
                        } else {
                            wrapped_has_restricted_sink = true;
                            for &p in gm.payload_args {
                                if !wrapped_payload.contains(&p) {
                                    wrapped_payload.push(p);
                                }
                            }
                        }
                    }
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
            if wrapped_has_restricted_sink && !wrapped_all_args_sink && !wrapped_payload.is_empty()
            {
                match &mut info.call.sink_payload_args {
                    Some(existing) => {
                        for p in wrapped_payload {
                            if !existing.contains(&p) {
                                existing.push(p);
                            }
                        }
                    }
                    None => info.call.sink_payload_args = Some(wrapped_payload),
                }
            }
        }
    }
}

/// Mutable sink metadata of a node under construction in `push_node`.
struct SinkSlots<'a> {
    labels: &'a mut SmallVec<[DataLabel; 2]>,
    payload_args: &'a mut Option<Vec<usize>>,
    gate_filters: &'a mut Vec<GateFilter>,
    destination_uses: &'a mut Option<Vec<String>>,
    reaching_uses: &'a mut Option<Vec<String>>,
}

impl SinkSlots<'_> {
    /// Remove `cap` from every sink label and gate filter, dropping the ones
    /// left empty.
    fn strip_sink_cap(&mut self, cap: Cap) {
        let mut stripped: SmallVec<[DataLabel; 2]> = SmallVec::new();
        for l in self.labels.drain(..) {
            match l {
                DataLabel::Sink(c) if c.intersects(cap) => {
                    let rest = c & !cap;
                    if !rest.is_empty() && !stripped.contains(&DataLabel::Sink(rest)) {
                        stripped.push(DataLabel::Sink(rest));
                    }
                }
                other => stripped.push(other),
            }
        }
        *self.labels = stripped;
        self.gate_filters.retain_mut(|f| {
            f.label_caps &= !cap;
            !f.label_caps.is_empty()
        });
        if !self.labels.iter().any(|l| matches!(l, DataLabel::Sink(_))) {
            *self.payload_args = None;
            *self.destination_uses = None;
            self.gate_filters.clear();
        }
    }

    fn sink_caps(&self) -> Cap {
        self.labels.iter().fold(Cap::empty(), |acc, l| match l {
            DataLabel::Sink(c) => acc | *c,
            _ => acc,
        })
    }
}

/// JS/TS tagged SQL templates.  A tag such as `prisma.$queryRaw` or the
/// drizzle / `Prisma.sql` `sql` tag sends each `${}` substitution as a bind
/// parameter, so neither the tagged call nor a SQL sink that receives it
/// (`db.execute(sql`...`)`) is an injection vector unless a substitution
/// splices raw text (`${Prisma.raw(col)}`, `${sql.raw(col)}`), see
/// [`js_sql_template_raw_splices`].
///
/// * The node's own call is a tagged SQL template: its SQL sink is limited
///   to the substitutions holding a raw splice, or dropped when there are
///   none.  A raw splice in an `sql` builder tag (which no flat rule labels)
///   makes it a sink; an `sql` builder without one returns a fragment that is
///   safe to hand to any executor, so its result is marked SQL-sanitised.
/// * A SQL sink whose payload arguments are all tagged SQL templates checks
///   only the identifiers inside their raw splices.
fn apply_js_sql_template_params(call: Node, code: &[u8], slots: &mut SinkSlots<'_>) {
    if let Some((positions, _)) = js_sql_template_raw_splices(call, code) {
        let has_sql_sink = slots.sink_caps().contains(Cap::SQL_QUERY);
        let is_builder = call
            .child_by_field_name("function")
            .and_then(|f| text_of(f, code))
            .is_some_and(|t| {
                let leaf = t.rsplit('.').next().unwrap_or(&t).trim();
                leaf.eq_ignore_ascii_case("sql")
            });
        if positions.is_empty() {
            if has_sql_sink {
                slots.strip_sink_cap(Cap::SQL_QUERY);
            }
            if is_builder {
                slots.labels.push(DataLabel::Sanitizer(Cap::SQL_QUERY));
            }
            return;
        }
        if !has_sql_sink {
            slots.labels.push(DataLabel::Sink(Cap::SQL_QUERY));
        }
        if slots.sink_caps() == Cap::SQL_QUERY {
            let narrowed: Vec<usize> = match slots.payload_args.as_ref() {
                Some(existing) => positions
                    .into_iter()
                    .filter(|p| existing.contains(p))
                    .collect(),
                None => positions,
            };
            *slots.payload_args = Some(narrowed.clone());
            slots.gate_filters.clear();
            *slots.destination_uses = None;
            if narrowed.is_empty() {
                slots.strip_sink_cap(Cap::SQL_QUERY);
            }
        }
        return;
    }

    // A SQL sink fed by tagged templates: `db.execute(sql`...`)`.
    if !slots.sink_caps().contains(Cap::SQL_QUERY) {
        return;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };
    if args.fkind() != "arguments" {
        return;
    }
    let arg_nodes: Vec<Node> = {
        let mut cursor = args.walk();
        args.named_children(&mut cursor).collect()
    };
    let positions: Vec<usize> = match slots.payload_args.as_ref() {
        Some(p) => p.clone(),
        None => (0..arg_nodes.len()).collect(),
    };
    let mut raw_idents: Vec<String> = Vec::new();
    let mut saw_template = false;
    for pos in positions {
        let Some(arg) = arg_nodes.get(pos) else {
            continue;
        };
        if let Some((_, idents)) = js_sql_template_raw_splices(*arg, code) {
            saw_template = true;
            raw_idents.extend(idents);
            continue;
        }
        // Any other payload argument that reads a variable may carry SQL
        // text of its own; leave the sink alone.
        let mut idents = Vec::new();
        collect_idents(*arg, code, &mut idents);
        if !idents.is_empty() {
            return;
        }
    }
    if !saw_template {
        return;
    }
    if raw_idents.is_empty() {
        slots.strip_sink_cap(Cap::SQL_QUERY);
    } else if slots.sink_caps() == Cap::SQL_QUERY {
        *slots.reaching_uses = Some(match slots.reaching_uses.take() {
            Some(existing) => raw_idents
                .into_iter()
                .filter(|u| existing.contains(u))
                .collect(),
            None => raw_idents,
        });
    }
}

/// Extra payload positions for a JS/TS `child_process` argv-taking sink
/// (`spawn`, `execFile`, ...) whose inline options object enables `shell`
/// (see [`js_shell_option_argv_positions`]).  Empty unless the node carries a
/// `SHELL_ESCAPE` sink and the callee's last segment is one of
/// [`crate::labels::javascript::CHILD_PROCESS_SHELL_OPTION_METHODS`].
fn js_shell_option_payload(
    lang: &str,
    callee: &str,
    labels: &[DataLabel],
    call_node: Node,
    code: &[u8],
) -> Vec<usize> {
    if !matches!(lang, "javascript" | "typescript" | "tsx") {
        return Vec::new();
    }
    if !labels
        .iter()
        .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SHELL_ESCAPE)))
    {
        return Vec::new();
    }
    let leaf = callee.rsplit('.').next().unwrap_or(callee);
    if !crate::labels::javascript::CHILD_PROCESS_SHELL_OPTION_METHODS.contains(&leaf) {
        return Vec::new();
    }
    js_shell_option_argv_positions(call_node, code)
}

/// Phase 05 — apply [`crate::labels::GatedLabelRule`] entries against
/// every call node in the file. The local-import view supplies the
/// gate evaluation context so a bare-name `readFile(...)` only fires
/// when the file actually imports `readFile` from `fs/promises` /
/// `node:fs/promises` (or is renamed via `import * as fsp` /
/// `import { readFile as rf }`). Strictly additive: only inserts new
/// labels, never removes existing ones.  A sink label this pass
/// contributes also carries its rule's payload positions
/// ([`crate::labels::GatedLabelRule::payload_args`]).
fn apply_gated_label_rules(
    bodies: &mut [BodyCfg],
    lang: &str,
    _extra: Option<&[crate::labels::RuntimeLabelRule]>,
    local_imports: &std::collections::HashMap<String, String>,
    tree: &Tree,
    code: &[u8],
) {
    let ctx = crate::labels::ClassificationContext {
        local_imports: Some(local_imports),
    };
    let root = tree.root_node();
    for body in bodies.iter_mut() {
        let indices: Vec<NodeIndex> = body.graph.node_indices().collect();
        for idx in indices {
            // The nested-call record was built before the import view
            // existed, so its per-call label facts miss the import-gated
            // rules (`cp.exec(f(x))` with `cp = require('child_process')`).
            if let Some(tree) = body.graph[idx].call.nested_calls.as_deref_mut() {
                for call in tree.calls.iter_mut().filter(|c| !c.callee.is_empty()) {
                    for m in crate::labels::classify_gated_matches(lang, &call.callee, Some(&ctx)) {
                        if m.chain_head {
                            continue;
                        }
                        call.labelled = true;
                        match m.label {
                            crate::labels::DataLabel::Source(bits) => call.label_source |= bits,
                            crate::labels::DataLabel::Sanitizer(bits) => call.label_strip |= bits,
                            crate::labels::DataLabel::Sink(_) => call.label_sink = true,
                        }
                    }
                }
            }
            let Some(callee) = body.graph[idx].call.callee.clone() else {
                continue;
            };
            let matches = crate::labels::classify_gated_matches(lang, &callee, Some(&ctx));
            if !matches.is_empty() {
                let (start, end) = body.graph[idx]
                    .call
                    .callee_span
                    .unwrap_or(body.graph[idx].ast.span);
                let cn = root
                    .descendant_for_byte_range(start, end)
                    .and_then(|n| find_call_node(n, lang));
                // Which call does the gated sink name?  The node's own call
                // when its function text matches directly (read from the AST:
                // `callee` may hold a member Source that `push_node` hoisted
                // out of the arguments).  Otherwise the rule matched the head
                // of the receiver chain (`execSync(cmd).toString()`), whose
                // arguments are not this node's positional arguments: restrict
                // the sink to the identifiers inside the head call's payload
                // arguments, and drop it when that payload is a constant.
                let has_gated_sink = matches
                    .iter()
                    .any(|m| matches!(m.label, crate::labels::DataLabel::Sink(_)));
                let own_call_matches = cn
                    .and_then(|c| c.child_by_field_name("function"))
                    .and_then(|f| call_fn_callee_text(f, lang, code))
                    .map(|t| t.chars().filter(|c| !c.is_whitespace()).collect::<String>())
                    .is_some_and(|t| {
                        crate::labels::classify_gated_matches(lang, &t, Some(&ctx))
                            .iter()
                            .any(|m| {
                                !m.chain_head
                                    && matches!(m.label, crate::labels::DataLabel::Sink(_))
                            })
                    });
                let head = cn.map(chain_head_call).filter(|h| Some(*h) != cn);
                let chain_reaching = match head {
                    Some(head) if has_gated_sink && !own_call_matches => {
                        let mut payload: Vec<usize> = Vec::new();
                        for m in &matches {
                            if matches!(m.label, crate::labels::DataLabel::Sink(_)) {
                                payload.extend(m.payload_args.iter().copied());
                            }
                        }
                        Some(inner_payload_idents(head, &payload, code))
                    }
                    _ => None,
                };
                let info = &mut body.graph[idx];
                let had_sink = info
                    .taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, crate::labels::DataLabel::Sink(_)));
                // Payload positions of the sinks this pass contributes.  A
                // label the node already carries keeps the payload set its
                // flat rule or `SinkGate` gave it.
                let mut payload: Vec<usize> = Vec::new();
                for m in matches {
                    let is_sink = matches!(m.label, crate::labels::DataLabel::Sink(_));
                    if info.taint.labels.contains(&m.label)
                        || (is_sink && chain_reaching.as_ref().is_some_and(|u| u.is_empty()))
                    {
                        continue;
                    }
                    info.taint.labels.push(m.label);
                    if is_sink {
                        payload.extend(m.payload_args.iter().copied());
                    }
                }
                payload.sort_unstable();
                payload.dedup();
                if let Some(uses) = chain_reaching {
                    if !uses.is_empty() && info.call.sink_reaching_uses.is_none() {
                        info.call.sink_reaching_uses = Some(uses);
                    }
                } else if !payload.is_empty() {
                    record_gated_sink_payload(info, payload, had_sink, &callee, cn, lang, code);
                }
                continue;
            }

            // The node's own callee is not an import-gated sink.  When the node
            // carries no `Sink` label of its own (a non-sink wrapper such as the
            // `JSON.parse` sanitizer or an unknown helper), re-walk its AST for a
            // nested import-gated sink that `push_node`'s CFG-time `classify`
            // could not resolve (the import view did not exist yet).  Surface it
            // the same way `find_inner_sink_call` does: rewrite the node's callee
            // to the inner sink and remember the outer callee.  vite CVE-2026-39365
            // (`JSON.parse(await fsp.readFile(tainted))`).
            if body.graph[idx]
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, crate::labels::DataLabel::Sink(_)))
            {
                continue;
            }
            let (start, end) = body.graph[idx].ast.span;
            let Some(node) = root.descendant_for_byte_range(start, end) else {
                continue;
            };
            if let Some((inner_text, inner, inner_span)) =
                helpers::find_inner_gated_sink_call(node, lang, code, &ctx)
            {
                // The "inner" call can be the node's own call: `push_node`
                // rewrote the callee of `spawn('ls', [req.query.dir])` to the
                // member Source in its arguments because the import-gated
                // `spawn` was not yet known to be a sink.  Restore the call's
                // identity (its `arg_uses` and argument literals belong to it)
                // and apply the rule's payload positions, as a CFG-time sink
                // label would have.
                let own_call = find_call_node(node, lang)
                    .filter(|cn| (cn.start_byte(), cn.end_byte()) == inner_span);
                // A genuinely nested sink (`upload(createReadStream(p), meta)`)
                // only receives its own payload arguments: restrict the scan
                // to the identifiers inside them, so a tainted sibling
                // argument of the wrapper (`meta`) is not its payload.  A
                // nested sink whose payload holds no identifier at all is a
                // constant and contributes nothing.
                // The same holds for the head of a chain matched through its
                // outer call (`execFileSync(bin).toString()`).
                let mut reaching: Option<Vec<String>> = None;
                if own_call.is_none() || inner.chain_head {
                    let mut uses = root
                        .descendant_for_byte_range(inner_span.0, inner_span.1)
                        .map(|c| {
                            if inner.chain_head {
                                chain_head_call(c)
                            } else {
                                c
                            }
                        })
                        .map(|c| inner_payload_idents(c, inner.payload_args, code))
                        .unwrap_or_default();
                    if uses.is_empty() {
                        continue;
                    }
                    // An inline member Source inside the nested call
                    // (`upload(createReadStream(req.query.p))`) is lowered as a
                    // synthetic `__nyx_src_*` binding of the wrapper argument
                    // that contains it; keep that binding reachable.
                    if let Some(pos) = find_call_node(node, lang)
                        .and_then(|outer| enclosing_arg_position(outer, inner_span))
                        && let Some(group) = body.graph[idx].call.arg_uses.get(pos)
                    {
                        uses.extend(group.iter().filter(|u| u.starts_with("__nyx_")).cloned());
                    }
                    reaching = Some(uses);
                }
                let nesting = if own_call.is_none() {
                    call_arg_nesting(node, inner_span)
                } else {
                    CalleeNesting::Own
                };
                let info = &mut body.graph[idx];
                info.taint.labels.push(inner.label);
                if nesting != CalleeNesting::Own {
                    info.call.callee_nesting = nesting;
                }
                if info.call.sink_reaching_uses.is_none() {
                    info.call.sink_reaching_uses = reaching;
                }
                if own_call.is_some() && !inner.chain_head {
                    if info.call.outer_callee.as_deref() == Some(inner_text.as_str()) {
                        info.call.outer_callee = None;
                        info.call.callee = Some(inner_text.clone());
                        info.call.callee_span = Some(inner_span);
                    }
                    if !inner.payload_args.is_empty() {
                        record_gated_sink_payload(
                            info,
                            inner.payload_args.to_vec(),
                            false,
                            &inner_text,
                            own_call,
                            lang,
                            code,
                        );
                    }
                } else if own_call.is_none() && info.call.outer_callee.is_none() {
                    info.call.outer_callee = Some(callee);
                    info.call.callee = Some(inner_text);
                    info.call.callee_span = Some(inner_span);
                }
            }
        }
    }
}

/// Innermost call of a method chain rooted at `call_node`
/// (`cp.execSync(cmd)` for `cp.execSync(cmd).toString().trim()`).
fn chain_head_call(call_node: Node) -> Node {
    let mut cur = call_node;
    while let Some(next) = cur
        .child_by_field_name("function")
        .filter(|f| f.fkind() == "member_expression")
        .and_then(|f| f.child_by_field_name("object"))
        .map(unwrap_parens)
        .filter(|o| o.fkind() == "call_expression")
    {
        cur = next;
    }
    cur
}

/// Classify how the node spanning `span` sits under `root`: directly in the
/// `arguments` of some call, through an aggregate literal inside such
/// arguments, or not in call arguments at all.
///
/// One top-down cursor descent from `root` to the smallest node spanning
/// `span` (the node `descendant_for_byte_range` returns).  The nearest
/// `arguments` edge above that node decides: an aggregate literal strictly
/// below it makes the nesting [`CalleeNesting::InAggregateArg`].  Walking up
/// with `parent()` instead costs a root-to-node descent per step.
fn call_arg_nesting(root: Node, span: (usize, usize)) -> CalleeNesting {
    let args_field = root.language().field_id_for_name("arguments");
    let mut cursor = root.walk();
    // Depth (in edges below `root`) of the deepest `arguments` child entered,
    // and of the deepest aggregate literal on the path.
    let mut args_depth: Option<usize> = None;
    let mut aggregate_depth: Option<usize> = None;
    let mut depth = 0usize;
    while cursor.goto_first_child_for_byte(span.0).is_some() {
        let child = cursor.node();
        if child.start_byte() > span.0 || child.end_byte() < span.1 {
            break;
        }
        depth += 1;
        if args_field.is_some() && cursor.field_id() == args_field {
            args_depth = Some(depth);
        }
        if is_aggregate_literal_kind(child.fkind()) {
            aggregate_depth = Some(depth);
        }
    }
    match args_depth {
        None => CalleeNesting::Own,
        Some(a) if aggregate_depth.is_some_and(|g| g > a) => CalleeNesting::InAggregateArg,
        Some(_) => CalleeNesting::InArg,
    }
}

/// The original bottom-up [`call_arg_nesting`], kept as the test oracle.
#[cfg(test)]
pub(super) fn call_arg_nesting_reference(root: Node, span: (usize, usize)) -> CalleeNesting {
    let Some(mut cur) = root.descendant_for_byte_range(span.0, span.1) else {
        return CalleeNesting::Own;
    };
    let mut via_aggregate = false;
    while cur.id() != root.id() {
        let Some(parent) = cur.parent() else {
            return CalleeNesting::Own;
        };
        if parent
            .child_by_field_name("arguments")
            .is_some_and(|a| a.id() == cur.id())
        {
            return if via_aggregate {
                CalleeNesting::InAggregateArg
            } else {
                CalleeNesting::InArg
            };
        }
        if is_aggregate_literal_kind(cur.fkind()) {
            via_aggregate = true;
        }
        cur = parent;
    }
    CalleeNesting::Own
}

#[cfg(test)]
pub(super) fn call_arg_nesting_for_test(root: Node, span: (usize, usize)) -> CalleeNesting {
    call_arg_nesting(root, span)
}

/// True when `call`, a descendant of the condition expression `root`, is
/// evaluated on every run of the condition: it is not the right operand of a
/// short-circuit operator and not a branch of a conditional expression.
fn runs_unconditionally(root: Node, call: Node) -> bool {
    let mut cur = call;
    while cur.id() != root.id() {
        let Some(parent) = cur.parent() else {
            return true;
        };
        let mut cursor = parent.walk();
        let short_circuit = parent
            .children(&mut cursor)
            .any(|c| !c.is_named() && matches!(c.fkind(), "&&" | "||" | "and" | "or" | "??" | "?"));
        let left_first = parent
            .named_child(0)
            .is_some_and(|first| first.id() == cur.id());
        if short_circuit && !left_first {
            return false;
        }
        cur = parent;
    }
    true
}

/// Grammar kinds of object / array / map / struct literals.
fn is_aggregate_literal_kind(kind: &str) -> bool {
    matches!(
        kind,
        "object"
            | "array"
            | "pair"
            | "dictionary"
            | "list"
            | "tuple"
            | "set"
            | "hash"
            | "array_initializer"
            | "array_creation_expression"
            | "initializer_list"
            | "composite_literal"
            | "literal_value"
            | "struct_expression"
            | "array_expression"
            | "tuple_expression"
    )
}

/// Positional index of the argument of `call_node` whose span contains
/// `span`.
fn enclosing_arg_position(call_node: Node, span: (usize, usize)) -> Option<usize> {
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .position(|a| a.start_byte() <= span.0 && span.1 <= a.end_byte())
}

/// Identifiers (dotted paths first) inside the payload arguments of
/// `call_node`, or inside every argument when `payload_args` is empty.
fn inner_payload_idents(call_node: Node, payload_args: &[usize], code: &[u8]) -> Vec<String> {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut idents = Vec::new();
    let mut paths = Vec::new();
    let mut cursor = args.walk();
    for (i, arg) in args.named_children(&mut cursor).enumerate() {
        if payload_args.is_empty() || payload_args.contains(&i) {
            collect_idents_with_paths(arg, code, &mut idents, &mut paths);
        }
    }
    paths.extend(idents);
    paths
}

/// Record the payload positions of a sink the gated post-pass attached to
/// `info`, widened for an enabled `child_process` `shell` option (mirrors the
/// `SinkGate` handling in `push_node`).  `had_sink` says whether the node
/// already carried a sink from a flat rule: restricting an unrestricted
/// (`None`) payload set is only sound when no earlier sink relies on every
/// argument being checked.
fn record_gated_sink_payload(
    info: &mut NodeInfo,
    mut payload: Vec<usize>,
    had_sink: bool,
    callee: &str,
    call_node: Option<Node>,
    lang: &str,
    code: &[u8],
) {
    if let Some(cn) = call_node {
        for p in js_shell_option_payload(lang, callee, &info.taint.labels, cn, code) {
            if !payload.contains(&p) {
                payload.push(p);
            }
        }
    }
    match &mut info.call.sink_payload_args {
        Some(existing) => {
            for p in payload {
                if !existing.contains(&p) {
                    existing.push(p);
                }
            }
        }
        None if !had_sink => {
            info.call.sink_payload_args = Some(payload);
        }
        None => {}
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
fn build_callee_site(
    callee: &str,
    info: &NodeInfo,
    lang: &str,
    code: &[u8],
) -> crate::summary::CalleeSite {
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

    let span = callee_span_line_col(code, info.ast.span.0);

    CalleeSite {
        name: callee.to_string(),
        arity,
        receiver,
        qualifier,
        ordinal: info.call.call_ordinal,
        span,
    }
}

/// Convert a byte offset into a 1-based `(line, col)` pair against `code`.
///
/// Returns `None` only when `code` is empty (no source to resolve against);
/// out-of-range offsets are clamped to `code.len()` so a synthetic node
/// whose span overshoots the file still produces the last-line coordinate
/// rather than `None`.
fn callee_span_line_col(code: &[u8], offset: usize) -> Option<(u32, u32)> {
    if code.is_empty() {
        return None;
    }
    let clamped = offset.min(code.len());
    let prefix = &code[..clamped];
    let line = prefix.iter().filter(|&&b| b == b'\n').count() as u32 + 1;
    let col_bytes = match prefix.iter().rposition(|&b| b == b'\n') {
        Some(idx) => clamped - idx - 1,
        None => clamped,
    } as u32
        + 1;
    Some((line, col_bytes))
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

#[cfg(test)]
mod cfg_tests;

/// For a Rust `recv_call(..).unwrap()` / `.expect(..)`, the receiver call.
///
/// Peels repeated unwraps (`f(..).unwrap().expect(..)` is unusual but legal)
/// and returns `None` when `call` is not an unwrap or its receiver is not
/// itself a call.
fn peel_rust_result_unwrap<'a>(call: Node<'a>, code: &[u8]) -> Option<Node<'a>> {
    let mut cur = call;
    let mut peeled = false;
    loop {
        if cur.fkind() != "call_expression" {
            break;
        }
        let function = cur.child_by_field_name("function")?;
        if function.fkind() != "field_expression" {
            break;
        }
        let method = function.child_by_field_name("field")?;
        let name = method.utf8_text(code).ok()?;
        if !matches!(name, "unwrap" | "expect") {
            break;
        }
        let recv = function.child_by_field_name("value")?;
        if recv.fkind() != "call_expression" {
            break;
        }
        cur = recv;
        peeled = true;
    }
    peeled.then_some(cur)
}
