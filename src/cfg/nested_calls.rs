//! Call nesting inside a single CFG node's expression.
//!
//! A statement like `html = "<p>" + escapeHtml(name) + "</p>" + bio` or
//! `res.send(card("static", b))` becomes one CFG node and one SSA `Call`.
//! The node keeps a single callee plus flat use lists, so on its own it cannot
//! say which operands a nested call actually wraps.  [`NestedCallTree`]
//! records that structure at CFG time: every call inside the expression, how
//! the calls nest, and for each value-use occurrence the innermost call it
//! sits in and at which argument position.  Taint transfer and sink
//! evaluation read it to apply a nested call's semantics (a sanitizer, a
//! callee summary) only to the operands that call encloses.
//!
//! Occurrence text uses the same forms as
//! [`super::collect_idents_with_paths`] (plain identifiers, dotted member
//! paths, PHP variables without `$`), so a tree entry lines up with the SSA
//! value lowering looked up for the same name.

use super::literals::{call_ident_of, ruby_implicit_call_arg};
use super::{member_expr_text, text_of};
use crate::cfg::fast_kind::FastKind;
use crate::labels::{Cap, DataLabel, Kind, RuntimeLabelRule, lookup};
use tree_sitter::Node;

/// Where an operand or a nested call sits inside the call that encloses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallSlot {
    /// Positional argument `n`, indexed like `CallMeta::arg_uses`.
    Arg(u16),
    /// The method receiver (`obj` in `obj.m(x)`).
    Receiver,
    /// Anything else: the callee name, a keyword argument value, or an
    /// argument of a call whose positions a splat hides.
    Other,
}

/// One call expression inside a CFG node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NestedCall {
    /// Callee text in the same form as `NodeInfo::arg_callees` entries.
    pub callee: String,
    /// Byte span of the call expression.
    pub span: (usize, usize),
    /// Index of the enclosing call, `None` when no other call of the node
    /// encloses this one.
    pub parent: Option<u16>,
    /// Slot of this call inside `parent`; `Other` when `parent` is `None`.
    pub slot: CallSlot,
    /// Positional argument count, `None` when a splat hides it.
    pub arity: Option<u16>,
    /// The call is a whole positional argument of `parent` (`f(g(x))`, not
    /// `f("a" + g(x))`), parentheses and `await` aside.
    pub exact_arg: bool,
    /// Caps of the callee's Source labels.
    pub label_source: Cap,
    /// Caps of the callee's Sanitizer labels.
    pub label_strip: Cap,
    /// The callee carries a Sink label or matches a gated sink.
    pub label_sink: bool,
    /// The callee carries any label.
    pub labelled: bool,
}

/// One value-use occurrence inside a CFG node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NestedUse {
    /// Identifier or dotted path text.
    pub text: String,
    /// Innermost call containing the occurrence, `None` when it sits outside
    /// every call of the node (a plain operand of the statement value).
    pub call: Option<u16>,
    /// Slot of the occurrence inside `call` (`Other` when `call` is `None`).
    pub slot: CallSlot,
}

/// Call nesting of one CFG node.  See the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NestedCallTree {
    /// Calls in pre-order: a call precedes the calls nested in it.
    pub calls: Vec<NestedCall>,
    /// The call the node's SSA op stands for (the one whose callee became
    /// `CallMeta::callee`), when it could be pinned to a call of the tree.
    pub anchor: Option<u16>,
    /// Value-use occurrences in source order.  Assignment targets are left
    /// out (they are written, not read), except for compound assignments.
    pub uses: Vec<NestedUse>,
}

impl NestedCallTree {
    /// Occurrences recorded for the identifier or path `name`.
    pub fn uses_of<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a NestedUse> + 'a {
        self.uses.iter().filter(move |u| u.text == name)
    }

    /// True when call `call` is `ancestor` or is nested inside it.
    pub fn call_within(&self, call: u16, ancestor: u16) -> bool {
        let mut cur = Some(call);
        while let Some(c) = cur {
            if c == ancestor {
                return true;
            }
            cur = self.calls.get(c as usize).and_then(|n| n.parent);
        }
        false
    }

    /// True when `name` occurs outside the anchor call at a spot that no
    /// call accepted by `confines` wraps: an operand of the enclosing
    /// expression that the anchor's result does not account for.  `false`
    /// without an anchor.
    pub fn occurs_beside_anchor(&self, name: &str, confines: impl Fn(&str) -> bool) -> bool {
        let Some(anchor) = self.anchor else {
            return false;
        };
        self.uses_of(name).any(|u| {
            let mut call = u.call;
            while let Some(c) = call {
                if c == anchor {
                    return false;
                }
                let node = &self.calls[c as usize];
                if confines(&node.callee) {
                    return false;
                }
                call = node.parent;
            }
            true
        })
    }

    /// True when the occurrence sits inside the anchor call (in one of its
    /// arguments, its receiver, or its callee position).
    pub fn use_within_anchor(&self, u: &NestedUse) -> bool {
        match (u.call, self.anchor) {
            (Some(c), Some(a)) => self.call_within(c, a),
            _ => false,
        }
    }
}

/// Build the call nesting record for a CFG node whose expression is `ast`.
///
/// Returns `None` when the flat per-node view is already exact (no call, or a
/// single call with every operand inside it) and for Rust macro invocations,
/// whose token trees carry no argument structure.  `anchor` is the byte span
/// of the call the node's callee text came from plus that text; the call at
/// the span becomes the anchor only when its own callee text matches.
pub(super) fn build_nested_call_tree(
    ast: Node,
    lang: &str,
    code: &[u8],
    anchor: Option<((usize, usize), &str)>,
    extra: Option<&[RuntimeLabelRule]>,
) -> Option<Box<NestedCallTree>> {
    if !needs_tree(ast, lang, code) {
        return None;
    }
    let mut b = Builder {
        lang,
        code,
        extra,
        tree: NestedCallTree::default(),
        bail: false,
        exact_args: Vec::new(),
    };
    b.walk(ast, None, CallSlot::Other);
    if b.bail || b.tree.calls.is_empty() {
        return None;
    }
    b.tree.anchor = anchor.and_then(|(span, text)| {
        b.tree
            .calls
            .iter()
            .position(|c| c.span == span && c.callee == text)
            .map(|i| i as u16)
    });
    Some(Box::new(b.tree))
}

/// Cheap allocation-free pre-check: does `ast` hold two or more calls, or one
/// call next to an operand outside it?
fn needs_tree(ast: Node, lang: &str, code: &[u8]) -> bool {
    fn scan(n: Node, lang: &str, code: &[u8], in_call: bool, calls: &mut u32, outside: &mut bool) {
        if *calls >= 2 {
            return;
        }
        let kind = n.fkind();
        match lookup(lang, kind) {
            Kind::Function => return,
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
                *calls += 1;
                let mut c = n.walk();
                for ch in n.children(&mut c) {
                    scan(ch, lang, code, true, calls, outside);
                }
                return;
            }
            _ => {}
        }
        if is_value_leaf(kind) {
            // A bare Ruby argument that is not a local is a call.
            if in_call && ruby_arg_is_implicit_call(n, lang, code).is_some() {
                *calls += 1;
            }
            if !in_call {
                *outside = true;
            }
            return;
        }
        let skip = assignment_target(n, kind, code);
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            if Some(ch) == skip {
                continue;
            }
            scan(ch, lang, code, in_call, calls, outside);
        }
    }
    let mut calls = 0u32;
    let mut outside = false;
    scan(ast, lang, code, false, &mut calls, &mut outside);
    calls >= 2 || (calls == 1 && outside)
}

/// The method name when `n` is a bare Ruby call argument that is not a local.
fn ruby_arg_is_implicit_call(n: Node, lang: &str, code: &[u8]) -> Option<String> {
    if lang != "ruby" || n.fkind() != "identifier" || n.parent()?.fkind() != "argument_list" {
        return None;
    }
    ruby_implicit_call_arg(n, lang, code)
}

fn is_value_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "field_identifier"
            | "property_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "variable_name"
    )
}

fn is_splat(kind: &str) -> bool {
    matches!(
        kind,
        "spread_element"
            | "dictionary_splat"
            | "list_splat"
            | "splat_argument"
            | "hash_splat_argument"
    )
}

/// The child of an assignment-like node that is only written: the target of
/// a plain assignment or the name of a declarator.  Compound assignments
/// (`x += y`) read their target, so nothing is skipped for them.
fn assignment_target<'a>(n: Node<'a>, kind: &str, code: &[u8]) -> Option<Node<'a>> {
    match kind {
        "assignment_expression" | "assignment" | "assignment_statement" => {
            if let Some(op) = n.child_by_field_name("operator")
                && !matches!(text_of(op, code).as_deref(), Some("=" | ":="))
            {
                return None;
            }
            n.child_by_field_name("left")
        }
        "short_var_declaration" => n.child_by_field_name("left"),
        "variable_declarator" | "var_spec" | "const_spec" => n.child_by_field_name("name"),
        "init_declarator" => n.child_by_field_name("declarator"),
        "let_declaration" => n.child_by_field_name("pattern"),
        _ => None,
    }
}

struct Builder<'c> {
    lang: &'c str,
    code: &'c [u8],
    extra: Option<&'c [RuntimeLabelRule]>,
    tree: NestedCallTree,
    bail: bool,
    /// Spans of calls that make up a whole positional argument.
    exact_args: Vec<(usize, usize)>,
}

/// The expression an argument node stands for: PHP wraps each argument in an
/// `argument` node, and parentheses, `await` and TS type assertions do not
/// change which call the argument is.
fn argument_expression(mut n: Node) -> Node {
    while matches!(
        n.fkind(),
        "argument"
            | "parenthesized_expression"
            | "await_expression"
            | "await"
            | "as_expression"
            | "satisfies_expression"
            | "non_null_expression"
    ) {
        match n.named_child(0) {
            Some(c) => n = c,
            None => break,
        }
    }
    n
}

impl Builder<'_> {
    fn push_use(&mut self, text: String, call: Option<u16>, slot: CallSlot) {
        let slot = if call.is_some() {
            slot
        } else {
            CallSlot::Other
        };
        self.tree.uses.push(NestedUse { text, call, slot });
    }

    fn walk(&mut self, n: Node, cur: Option<u16>, slot: CallSlot) {
        if self.bail {
            return;
        }
        if let Some(callee) = ruby_arg_is_implicit_call(n, self.lang, self.code) {
            self.push_implicit_call(n, callee, cur, slot);
            return;
        }
        match lookup(self.lang, n.fkind()) {
            Kind::Function => return,
            Kind::CallMacro => {
                // A macro's arguments are a flat token tree, so which
                // operand sits where is unknown.
                self.bail = true;
                return;
            }
            Kind::CallFn | Kind::CallMethod => {
                self.walk_call(n, cur, slot);
                return;
            }
            _ => {}
        }
        match n.fkind() {
            "variable_name" => {
                if let Some(t) = text_of(n, self.code) {
                    self.push_use(t.trim_start_matches('$').to_string(), cur, slot);
                }
                return;
            }
            k if is_value_leaf(k) => {
                if let Some(t) = text_of(n, self.code) {
                    self.push_use(t, cur, slot);
                }
                return;
            }
            "member_expression" | "attribute" | "selector_expression" | "field_expression" => {
                if let Some(path) = member_expr_text(n, self.code) {
                    self.push_use(path, cur, slot);
                }
            }
            "keyword_argument" | "named_argument" => {
                // Only the value is read; the keyword is a parameter name.
                if let Some(v) = n.child_by_field_name("value") {
                    self.walk(v, cur, slot);
                }
                return;
            }
            _ => {}
        }
        let skip = assignment_target(n, n.fkind(), self.code);
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            if Some(ch) == skip {
                continue;
            }
            self.walk(ch, cur, slot);
        }
    }

    /// A bare Ruby argument that is a zero-argument method call
    /// ([`ruby_implicit_call_arg`]): a call with no labels of its own, so only
    /// its callee summary can say what it returns.
    fn push_implicit_call(&mut self, n: Node, callee: String, parent: Option<u16>, slot: CallSlot) {
        if self.tree.calls.len() >= u16::MAX as usize {
            self.bail = true;
            return;
        }
        self.tree.calls.push(NestedCall {
            callee,
            span: (n.start_byte(), n.end_byte()),
            parent,
            slot: if parent.is_some() {
                slot
            } else {
                CallSlot::Other
            },
            arity: Some(0),
            exact_arg: parent.is_some(),
            label_source: Cap::empty(),
            label_strip: Cap::empty(),
            label_sink: false,
            labelled: false,
        });
    }

    fn walk_call(&mut self, call: Node, parent: Option<u16>, slot: CallSlot) {
        if self.tree.calls.len() >= u16::MAX as usize {
            self.bail = true;
            return;
        }
        let idx = self.tree.calls.len() as u16;
        let callee = call_ident_of(call, self.lang, self.code).unwrap_or_default();
        let mut label_source = Cap::empty();
        let mut label_strip = Cap::empty();
        let mut label_sink = false;
        let mut labelled = false;
        if !callee.is_empty() {
            // A Java stream accessor on a child process or a local resource
            // carries no Source label (see `java_stream_source_is_local`).
            let local_stream =
                self.lang == "java" && super::java_stream_source_is_local(call, self.code);
            for l in crate::labels::classify_all(self.lang, &callee, self.extra) {
                if local_stream && matches!(l, DataLabel::Source(_)) {
                    continue;
                }
                labelled = true;
                match l {
                    DataLabel::Source(bits) => label_source |= bits,
                    DataLabel::Sanitizer(bits) => label_strip |= bits,
                    DataLabel::Sink(_) => label_sink = true,
                }
            }
            label_sink |= !crate::labels::classify_gated_sink(
                self.lang,
                &callee,
                |_| None,
                |_| None,
                |_| false,
            )
            .is_empty();
        }
        self.tree.calls.push(NestedCall {
            callee,
            span: (call.start_byte(), call.end_byte()),
            parent,
            slot: if parent.is_some() {
                slot
            } else {
                CallSlot::Other
            },
            arity: None,
            exact_arg: parent.is_some()
                && self
                    .exact_args
                    .contains(&(call.start_byte(), call.end_byte())),
            label_source,
            label_strip,
            label_sink,
            labelled,
        });

        // Receiver: a field on the call itself (Java/PHP/Ruby) or the object
        // of a member-like callee (JS/TS/Python/Go/Rust/C).
        let recv_field = call
            .child_by_field_name("object")
            .or_else(|| call.child_by_field_name("receiver"))
            .or_else(|| call.child_by_field_name("scope"));
        let func = call.child_by_field_name("function");
        let func_recv = func.and_then(|f| match f.fkind() {
            "member_expression" | "attribute" => f.child_by_field_name("object"),
            "field_expression" => f.child_by_field_name("value"),
            "selector_expression" => f.child_by_field_name("operand"),
            _ => None,
        });

        // Positional arguments, indexed exactly like `extract_arg_uses`: one
        // slot per named child of the argument list, keyword arguments
        // skipped, and no positions at all once a splat appears.
        let args_node = call.child_by_field_name("arguments");
        if let Some(args) = args_node {
            let children: Vec<Node> = {
                let mut c = args.walk();
                args.named_children(&mut c).collect()
            };
            let positional = !children.iter().any(|ch| is_splat(ch.fkind()));
            let mut pos: u16 = 0;
            for ch in children {
                if matches!(ch.fkind(), "keyword_argument" | "named_argument") {
                    self.walk(ch, Some(idx), CallSlot::Other);
                    continue;
                }
                let s = if positional {
                    CallSlot::Arg(pos)
                } else {
                    CallSlot::Other
                };
                let expr = argument_expression(ch);
                if matches!(
                    lookup(self.lang, expr.fkind()),
                    Kind::CallFn | Kind::CallMethod
                ) {
                    self.exact_args.push((expr.start_byte(), expr.end_byte()));
                }
                self.walk(ch, Some(idx), s);
                pos = pos.saturating_add(1);
            }
            if positional {
                self.tree.calls[idx as usize].arity = Some(pos);
            }
        } else if call.fkind() == "subshell" {
            // Ruby backticks: each interpolation is a positional argument of
            // the synthetic `subshell` callee (see `extract_arg_uses`).
            let mut pos: u16 = 0;
            let mut c = call.walk();
            for ch in call.named_children(&mut c) {
                if ch.fkind() == "interpolation" {
                    self.walk(ch, Some(idx), CallSlot::Arg(pos));
                    pos = pos.saturating_add(1);
                }
            }
            self.tree.calls[idx as usize].arity = Some(pos);
            return;
        } else {
            self.tree.calls[idx as usize].arity = Some(0);
        }

        let mut c = call.walk();
        for ch in call.children(&mut c) {
            if Some(ch) == args_node {
                continue;
            }
            if Some(ch) == func {
                match func_recv {
                    // Method name is not a value use; only the receiver is.
                    Some(r) => self.walk(r, Some(idx), CallSlot::Receiver),
                    None => self.walk(ch, Some(idx), CallSlot::Other),
                }
                continue;
            }
            if Some(ch) == recv_field {
                self.walk(ch, Some(idx), CallSlot::Receiver);
                continue;
            }
            self.walk(ch, Some(idx), CallSlot::Other);
        }
    }
}
