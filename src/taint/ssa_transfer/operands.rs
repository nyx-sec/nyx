//! Per-operand taint for CFG nodes whose expression nests calls.
//!
//! One CFG node (and one SSA `Call`) can stand for a whole expression such as
//! `"<p>" + escapeHtml(name) + "</p>" + bio` or `res.send(card("static", b))`.
//! The SSA op keeps a single callee and flat argument groups, so applying the
//! callee's (or a wrapper's) semantics node-wide would sanitize, or drop,
//! operands the call never touches.  [`crate::cfg::NestedCallTree`] records
//! which calls enclose each operand occurrence; this module turns that record
//! into taint:
//!
//! * a value's contribution is computed per occurrence by applying, from the
//!   innermost wrapping call outwards, each wrapping call's effect on the slot
//!   the occurrence sits in ([`WrapEffect`]);
//! * the Call transfer feeds the callee only the operands inside the anchor
//!   call and adds the other operands ("siblings") through their own wrapping
//!   calls ([`split_call_operands`], [`sibling_taint`]);
//! * the sink check narrows each tainted value by the calls that wrap it below
//!   the sink call ([`refine_sink_values`]);
//! * a source call nested in the expression (`exec(getCmd(r))`,
//!   `siteHeader() + getCmd()`) contributes its own taint, which no SSA value
//!   carries otherwise ([`add_nested_source_values`],
//!   [`NestedOperands::expression_sources`]).
//!
//! Values are matched to occurrences by SSA `var_name`, the same text SSA
//! lowering used to look the value up; a pre-emitted inline member source is
//! matched through the member reads at its argument position.  A value with
//! no recorded occurrence keeps the node-wide behaviour.

use super::{
    ResolvedSummary, SsaTaintState, SsaTaintTransfer, effective_param_sanitizer,
    resolve_callee_hinted,
};
use crate::cfg::{CallSlot, NestedCallTree, NestedUse, NodeInfo};
use crate::labels::{Cap, DataLabel};
use crate::ssa::ir::{SsaBody, SsaValue};
use crate::summary::ssa_summary::TaintTransform;
use crate::taint::domain::TaintOrigin;
use smallvec::SmallVec;
use std::cell::OnceCell;
use std::rc::Rc;

/// The nested-call record of one node, with each call's callee summary
/// resolved on first use (label facts come precomputed from the CFG).
pub(super) struct NestedOperands<'a, 't> {
    tree: &'a NestedCallTree,
    anchor: u16,
    info: &'a NodeInfo,
    transfer: &'a SsaTaintTransfer<'t>,
    summaries: Vec<OnceCell<Option<Rc<ResolvedSummary>>>>,
}

impl<'a, 't> NestedOperands<'a, 't> {
    /// `None` unless the node has a nested-call record whose anchor call is
    /// known.
    pub(super) fn new(info: &'a NodeInfo, transfer: &'a SsaTaintTransfer<'t>) -> Option<Self> {
        let tree = info.call.nested_calls.as_deref()?;
        let anchor = tree.anchor?;
        Some(Self {
            tree,
            anchor,
            info,
            transfer,
            summaries: (0..tree.calls.len()).map(|_| OnceCell::new()).collect(),
        })
    }

    /// The record of a node whose expression is one statement-level call
    /// chain (`sb.append(a).append(esc(b))`), anchored on the outermost
    /// call.  Used where the node's own callee text does not identify a
    /// call of the record, so [`Self::new`] has no anchor.
    pub(super) fn for_call_chain(
        info: &'a NodeInfo,
        transfer: &'a SsaTaintTransfer<'t>,
    ) -> Option<Self> {
        let tree = info.call.nested_calls.as_deref()?;
        let anchor = tree.calls.iter().position(|c| c.parent.is_none())? as u16;
        Some(Self {
            tree,
            anchor,
            info,
            transfer,
            summaries: (0..tree.calls.len()).map(|_| OnceCell::new()).collect(),
        })
    }

    /// Callee summary of call `c`, when one resolves.
    fn summary(&self, c: u16) -> Option<&ResolvedSummary> {
        self.summaries[c as usize]
            .get_or_init(|| {
                let call = &self.tree.calls[c as usize];
                if call.callee.is_empty() {
                    return None;
                }
                resolve_callee_hinted(
                    self.transfer,
                    &call.callee,
                    self.info.ast.enclosing_func.as_deref().unwrap_or(""),
                    self.info.call.call_ordinal,
                    call.arity.map(usize::from),
                )
            })
            .as_deref()
    }

    /// What call `c` does to the taint of an operand in `slot`: its summary
    /// transfer for that parameter, then its Sanitizer labels (the order the
    /// Call transfer applies them in).  A call with neither passes taint
    /// through, as the Call transfer's default propagation does.
    fn apply(&self, c: u16, slot: CallSlot, caps: Cap, state: &SsaTaintState) -> Cap {
        let after = match self.summary(c) {
            None => caps,
            Some(r) => match slot {
                CallSlot::Arg(i) => {
                    let i = i as usize;
                    if !r.propagates_taint {
                        Cap::empty()
                    } else if r.propagating_params.is_empty() {
                        caps & !r.sanitizer_caps
                    } else if r.propagating_params.contains(&i) {
                        caps & !effective_param_sanitizer(r, i, state)
                    } else {
                        Cap::empty()
                    }
                }
                CallSlot::Receiver => match &r.receiver_to_return {
                    Some(TaintTransform::StripBits(bits)) => caps & !*bits,
                    _ => caps,
                },
                CallSlot::Other => caps,
            },
        };
        after & !self.tree.calls[c as usize].label_strip
    }

    /// Caps call `c` returns as a source: its Source labels, or (when
    /// `with_summary`) the internal-source caps of its summary.
    fn source(&self, c: u16, with_summary: bool) -> Cap {
        let labelled = self.tree.calls[c as usize].label_source;
        if !labelled.is_empty() || !with_summary {
            return labelled;
        }
        self.summary(c).map_or(Cap::empty(), |r| r.source_caps)
    }

    fn occurrences(&self, v: SsaValue, ssa: &SsaBody) -> impl Iterator<Item = &'a NestedUse> + 'a {
        value_occurrences(self.tree, v, ssa)
    }

    /// True when call `c` is a sink of its own: a Sink label, a gated sink,
    /// or a callee summary with internal sinks.
    fn is_sink_call(&self, c: u16) -> bool {
        self.tree.calls[c as usize].label_sink
            || self
                .summary(c)
                .is_some_and(|r| !r.sink_caps.is_empty() || !r.param_to_sink.is_empty())
    }

    /// The record of a sink node, anchored on the call that is the sink, so
    /// the operands inside it are its payload.  A chained call takes its
    /// text from the outer call and its label from the head of the chain
    /// (`exec.Command("sh", "-c", cmd).Run()` classifies as `exec.Command`),
    /// so the anchor moves down the receiver chain to the innermost call of
    /// the run of sinks it starts.  `None` when the anchor's receiver chain
    /// holds no sink (a label taken from an assignment target or from
    /// type-qualified resolution), which leaves the node to the node-wide
    /// sink check.
    pub(super) fn for_sink(info: &'a NodeInfo, transfer: &'a SsaTaintTransfer<'t>) -> Option<Self> {
        let mut ops = Self::new(info, transfer)?;
        let mut cur = ops.anchor;
        let mut found = None;
        loop {
            if ops.is_sink_call(cur) {
                found = Some(cur);
            } else if found.is_some() {
                break;
            }
            match ops
                .tree
                .calls
                .iter()
                .position(|c| c.parent == Some(cur) && c.slot == CallSlot::Receiver)
            {
                Some(next) => cur = next as u16,
                None => break,
            }
        }
        ops.anchor = found?;
        Some(ops)
    }

    /// True when no other call of the node encloses the anchor call.
    fn anchor_is_outermost(&self) -> bool {
        self.tree.calls[self.anchor as usize].parent.is_none()
    }

    /// True when the Call transfer can treat the anchor apart from the rest
    /// of the expression: the anchor is outermost, or every call enclosing
    /// it passes its arguments through untouched (no summary, no label, not
    /// a container operation, not a constructor), like
    /// `String.format("%s %s", escape(a), b)`.  An enclosing call with its
    /// own semantics (`parts.add(req.getParameter(k))`, a wrapper summary)
    /// is modelled together with the anchor by the Call transfer, which
    /// reads the op's argument groups and receiver as that call's.
    pub(super) fn anchor_separable(&self, info: &NodeInfo, lang: crate::symbol::Lang) -> bool {
        if self.anchor_is_outermost() {
            return true;
        }
        if info.call.is_constructor {
            return false;
        }
        let mut cur = self.tree.calls[self.anchor as usize].parent;
        while let Some(c) = cur {
            let call = &self.tree.calls[c as usize];
            if call.callee.is_empty()
                || call.labelled
                || self.summary(c).is_some()
                || crate::ssa::pointsto::classify_container_op(&call.callee, lang).is_some()
                || crate::pointer::is_container_write_callee(&call.callee)
            {
                return false;
            }
            cur = call.parent;
        }
        true
    }

    fn within_anchor(&self, u: &NestedUse) -> bool {
        self.tree.use_within_anchor(u)
    }

    /// Caps of one occurrence after the calls that wrap it, from the
    /// innermost call outwards.  The walk stops below the anchor call when
    /// the occurrence sits inside it, and at the top of the expression
    /// otherwise.
    fn occurrence_caps(&self, u: &NestedUse, mut caps: Cap, state: &SsaTaintState) -> Cap {
        let mut call = u.call;
        let mut slot = u.slot;
        while let Some(c) = call {
            if c == self.anchor || caps.is_empty() {
                break;
            }
            caps = self.apply(c, slot, caps, state);
            let node = &self.tree.calls[c as usize];
            call = node.parent;
            slot = node.slot;
        }
        caps
    }

    /// Caps `v` carries past the calls wrapping it.  `None` when the value
    /// has no recorded occurrence in the node.
    pub(super) fn value_caps(
        &self,
        v: SsaValue,
        caps: Cap,
        ssa: &SsaBody,
        state: &SsaTaintState,
    ) -> Option<Cap> {
        let mut seen = false;
        let mut out = Cap::empty();
        for u in self.occurrences(v, ssa) {
            seen = true;
            out |= self.occurrence_caps(u, caps, state);
        }
        seen.then_some(out)
    }

    /// [`Self::value_caps`] for a value appended to a string builder: an
    /// occurrence that only feeds a predicate (`x.isEmpty() ? a : b`,
    /// `"k".equals(x)`) contributes nothing, since the call yields a boolean
    /// or a length and the text of `x` does not reach the builder through it.
    pub(super) fn builder_value_caps(
        &self,
        v: SsaValue,
        caps: Cap,
        ssa: &SsaBody,
        state: &SsaTaintState,
    ) -> Option<Cap> {
        let mut seen = false;
        let mut out = Cap::empty();
        for u in self.occurrences(v, ssa) {
            seen = true;
            let feeds_predicate = u.call.is_some_and(|c| {
                is_value_predicate(crate::labels::bare_method_name(
                    &self.tree.calls[c as usize].callee,
                ))
            });
            if !feeds_predicate {
                out |= self.occurrence_caps(u, caps, state);
            }
        }
        seen.then_some(out)
    }

    /// Source calls nested inside the anchor call's arguments
    /// (`exec(getCmd(r))`, `system(getenv("CMD"))`).  Each comes back with
    /// the caps that survive the calls between it and the anchor, the anchor
    /// slot it feeds, the callee text, its span, and whether a call matching
    /// `confines` sits on that path.
    pub(super) fn nested_sources(
        &self,
        state: &SsaTaintState,
        confines: impl Fn(&str) -> bool,
    ) -> SmallVec<[NestedSource<'a>; 1]> {
        let mut out = SmallVec::new();
        for (i, call) in self.tree.calls.iter().enumerate() {
            let i = i as u16;
            if i == self.anchor || !self.tree.call_within(i, self.anchor) {
                continue;
            }
            let source = self.source(i, true);
            if source.is_empty() {
                continue;
            }
            let mut caps = source;
            let mut slot = call.slot;
            let mut cur = call.parent;
            let mut confined = false;
            while let Some(c) = cur {
                if c == self.anchor {
                    break;
                }
                let node = &self.tree.calls[c as usize];
                confined |= confines(&node.callee);
                caps = self.apply(c, slot, caps, state);
                slot = node.slot;
                cur = node.parent;
            }
            if caps.is_empty() {
                continue;
            }
            out.push(NestedSource {
                caps,
                slot,
                callee: &call.callee,
                span: call.span,
                confined,
                via_summary: call.label_source.is_empty(),
            });
        }
        out
    }
}

impl NestedOperands<'_, '_> {
    /// Taint that source calls nested in the expression add to the value of
    /// the op: a source inside the anchor call's arguments flows through the
    /// calls up to and including the anchor; a source beside the anchor
    /// (`siteHeader() + getCmd()`) flows through its own wrapping calls.
    pub(super) fn expression_sources(
        &self,
        info: &NodeInfo,
        node: petgraph::graph::NodeIndex,
        state: &SsaTaintState,
        lang: crate::symbol::Lang,
    ) -> (Cap, SmallVec<[TaintOrigin; 2]>) {
        let mut caps_out = Cap::empty();
        let mut origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        // A member source pre-emitted as its own node already carries the
        // node's inline source; adding the nested call would report it twice.
        if !self.anchor_separable(info, lang)
            || info
                .taint
                .uses
                .iter()
                .any(|u| u.starts_with(SYNTH_SOURCE_PREFIX))
        {
            return (caps_out, origins);
        }
        for (i, call) in self.tree.calls.iter().enumerate() {
            let i = i as u16;
            // Calls enclosing the anchor pass their arguments through (see
            // `anchor_separable`) and carry no source of their own.  Only
            // labelled sources are looked at here: this runs on every visit
            // of the op, and a summary lookup per nested call would cost more
            // than the rare `siteHeader() + getCmd()` shape is worth.  The
            // sink check covers summary sources (`exec(getCmd())`).
            if i == self.anchor || self.tree.call_within(self.anchor, i) {
                continue;
            }
            let source = self.source(i, false);
            if source.is_empty() {
                continue;
            }
            let mut caps = source;
            let mut slot = call.slot;
            let mut cur = call.parent;
            let mut on_receiver_chain = false;
            while let Some(c) = cur {
                if caps.is_empty() {
                    break;
                }
                if c == self.anchor {
                    // A call on the anchor's receiver chain is part of the
                    // anchor expression itself (`env::var("X").unwrap()`),
                    // whose labels the op already applies.
                    on_receiver_chain = !matches!(slot, CallSlot::Arg(_));
                    caps = self.apply(c, slot, caps, state);
                    break;
                }
                caps = self.apply(c, slot, caps, state);
                let n = &self.tree.calls[c as usize];
                slot = n.slot;
                cur = n.parent;
            }
            if caps.is_empty() || on_receiver_chain {
                continue;
            }
            caps_out |= caps;
            super::push_origin_bounded(
                &mut origins,
                TaintOrigin {
                    node,
                    source_kind: crate::labels::infer_source_kind(source, &call.callee),
                    source_span: Some(call.span),
                },
            );
        }
        (caps_out, origins)
    }
}

/// Methods whose result is a boolean or a number derived from the receiver
/// and arguments, never their text.
fn is_value_predicate(method: &str) -> bool {
    matches!(
        method,
        "isEmpty"
            | "isBlank"
            | "length"
            | "size"
            | "equals"
            | "equalsIgnoreCase"
            | "contains"
            | "startsWith"
            | "endsWith"
            | "matches"
            | "hashCode"
            | "indexOf"
            | "lastIndexOf"
            | "compareTo"
            | "isPresent"
    )
}

/// A source call nested inside a sink call's arguments.  See
/// [`NestedOperands::nested_sources`].
pub(super) struct NestedSource<'a> {
    pub(super) caps: Cap,
    pub(super) slot: CallSlot,
    pub(super) callee: &'a str,
    pub(super) span: (usize, usize),
    pub(super) confined: bool,
    /// The source caps come from the callee summary, not a label.
    pub(super) via_summary: bool,
}

/// Cheap pre-check for [`NestedOperands::expression_sources`]: the node has
/// an anchor and another call labelled as a source.
pub(super) fn may_hold_nested_sources(info: &NodeInfo) -> bool {
    info.call.nested_calls.as_deref().is_some_and(|t| {
        t.anchor.is_some_and(|a| {
            t.calls
                .iter()
                .enumerate()
                .any(|(i, c)| i != a as usize && !c.label_source.is_empty())
        })
    })
}

/// Operands of a Call op split around its anchor call.
pub(super) struct OperandSplit {
    /// The op's argument groups with every value that only occurs outside
    /// the anchor call removed.  Group count and order are unchanged.
    pub(super) callee_args: Vec<SmallVec<[SsaValue; 2]>>,
    /// The receiver, or `None` when it only occurs outside the anchor call.
    pub(super) callee_receiver: Option<SsaValue>,
    /// Values with at least one occurrence outside the anchor call.
    pub(super) siblings: SmallVec<[SsaValue; 4]>,
}

/// Split a Call op's operands into those the anchor call consumes and the
/// sibling operands of the enclosing expression.  `None` when the node has
/// no usable record or no sibling operand, which leaves the Call transfer
/// exactly as before.
///
/// The caller must also check [`NestedOperands::anchor_separable`] for a
/// nested anchor.
pub(super) fn split_call_operands(
    info: &NodeInfo,
    ssa: &SsaBody,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: Option<SsaValue>,
) -> Option<OperandSplit> {
    let tree = info.call.nested_calls.as_deref()?;
    let anchor = tree.anchor?;
    // (inside, outside) occurrence presence for one value.
    let place = |v: SsaValue| -> (bool, bool) {
        let Some(name) = ssa
            .value_defs
            .get(v.0 as usize)
            .and_then(|d| d.var_name.as_deref())
        else {
            return (true, false);
        };
        let mut inside = false;
        let mut outside = false;
        let mut any = false;
        for u in tree.uses_of(name) {
            any = true;
            if u.call.is_some_and(|c| tree.call_within(c, anchor)) {
                inside = true;
            } else {
                outside = true;
            }
        }
        if !any {
            // Unknown placement: keep the value on the callee side.
            return (true, false);
        }
        (inside, outside)
    };
    let mut siblings: SmallVec<[SsaValue; 4]> = SmallVec::new();
    let mut callee_args: Vec<SmallVec<[SsaValue; 2]>> = Vec::with_capacity(args.len());
    for group in args {
        let mut kept: SmallVec<[SsaValue; 2]> = SmallVec::new();
        for &v in group {
            let (inside, outside) = place(v);
            if outside && !siblings.contains(&v) {
                siblings.push(v);
            }
            if inside {
                kept.push(v);
            }
        }
        callee_args.push(kept);
    }
    let callee_receiver = match receiver {
        Some(r) => {
            let (inside, outside) = place(r);
            if outside && !siblings.contains(&r) {
                siblings.push(r);
            }
            inside.then_some(r)
        }
        None => None,
    };
    if siblings.is_empty() {
        return None;
    }
    Some(OperandSplit {
        callee_args,
        callee_receiver,
        siblings,
    })
}

/// Taint the sibling operands add to the value of the enclosing expression.
pub(super) struct SiblingTaint {
    pub(super) caps: Cap,
    pub(super) origins: SmallVec<[TaintOrigin; 2]>,
    /// Every sibling that contributes taint is in `validated_must`.
    pub(super) all_validated: bool,
}

impl Default for SiblingTaint {
    fn default() -> Self {
        Self {
            caps: Cap::empty(),
            origins: SmallVec::new(),
            all_validated: true,
        }
    }
}

/// Union the sibling operands' taint, each occurrence passed through the
/// calls that wrap it (none of which is the anchor call).
pub(super) fn sibling_taint(
    ops: &NestedOperands,
    siblings: &[SsaValue],
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &SsaTaintState,
) -> SiblingTaint {
    let mut out = SiblingTaint::default();
    for &v in siblings {
        let Some(t) = state.get(v) else {
            continue;
        };
        let mut caps = Cap::empty();
        for u in ops.occurrences(v, ssa) {
            if !ops.within_anchor(u) {
                caps |= ops.occurrence_caps(u, t.caps, state);
            }
        }
        if caps.is_empty() {
            continue;
        }
        out.caps |= caps;
        for o in &t.origins {
            super::push_origin_bounded(&mut out.origins, *o);
        }
        let validated = ssa
            .value_defs
            .get(v.0 as usize)
            .and_then(|d| d.var_name.as_deref())
            .and_then(|n| transfer.interner.get(n))
            .is_some_and(|sym| state.validated_must.contains(sym));
        out.all_validated &= validated;
    }
    out
}

/// Narrow tainted sink values by the calls that wrap them below the sink
/// call.  A value keeps only the caps that survive its wrapping calls (a
/// sanitizer, a summary that drops or strips that parameter); a value with
/// no recorded occurrence takes `legacy_strip`, the node-wide strip the sink
/// check applied before.  Values left with no cap in `sink_caps` are dropped.
///
/// A pre-emitted inline member source (`__nyx_src_*`, bound to one argument
/// position) stands for the member reads that classify as sources in that
/// argument; it keeps the caps that survive the wrapping calls of any of
/// them.  So `res.send(escapeHtml(req.query.a) + req.query.b)` still fires
/// through the raw `req.query.b`, while `res.send(escapeHtml(req.query.a))`
/// does not.
#[allow(clippy::too_many_arguments)]
pub(super) fn refine_sink_values(
    ops: &NestedOperands,
    info: &NodeInfo,
    transfer: &SsaTaintTransfer,
    tainted: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    ssa: &SsaBody,
    state: &SsaTaintState,
    legacy_strip: Cap,
    sink_caps: Cap,
) {
    for (v, caps, _) in tainted.iter_mut() {
        let name = ssa
            .value_defs
            .get(v.0 as usize)
            .and_then(|d| d.var_name.as_deref());
        let refined = match name {
            Some(n) if n.starts_with(SYNTH_SOURCE_PREFIX) => {
                ops.synth_source_caps(info, transfer, n, *caps, state)
            }
            _ => ops.value_caps(*v, *caps, ssa, state),
        };
        *caps = refined.unwrap_or(*caps & !legacy_strip);
    }
    tainted.retain(|(_, caps, _)| !(*caps & sink_caps).is_empty());
}

/// Prefix of the variables `pre_emit_arg_source_nodes` binds to an argument
/// position for an inline member source.
const SYNTH_SOURCE_PREFIX: &str = "__nyx_src_";

/// Source caps of a member read under the rule the CFG uses to pre-emit
/// inline member sources (`first_member_label`): any label on the full path,
/// then a Source label on a shorter prefix (`process.env.CMD` reads the
/// `process.env` source).
fn member_source_caps(transfer: &SsaTaintTransfer, text: &str) -> Cap {
    if !text.contains('.') {
        return Cap::empty();
    }
    let lang = transfer.lang.as_str();
    let mut candidate = text;
    let mut full = true;
    loop {
        match crate::labels::classify(lang, candidate, transfer.extra_labels) {
            Some(DataLabel::Source(bits)) => return bits,
            Some(_) if full => return Cap::empty(),
            _ => {}
        }
        full = false;
        match candidate.rsplit_once('.') {
            Some((prefix, _)) => candidate = prefix,
            None => return Cap::empty(),
        }
    }
}

impl NestedOperands<'_, '_> {
    /// Slot of the anchor call an occurrence feeds, `None` when it sits
    /// outside the anchor.
    fn anchor_slot(&self, u: &NestedUse) -> Option<CallSlot> {
        let mut call = u.call?;
        let mut slot = u.slot;
        loop {
            if call == self.anchor {
                return Some(slot);
            }
            let node = &self.tree.calls[call as usize];
            slot = node.slot;
            call = node.parent?;
        }
    }

    /// Caps a pre-emitted member-source binding keeps: the union, over the
    /// member reads in its argument that classify as sources, of what
    /// survives each read's wrapping calls.  `None` when the binding cannot
    /// be placed (a nested anchor, whose positions the binding does not
    /// index, or no source read recorded at that position).
    fn synth_source_caps(
        &self,
        info: &NodeInfo,
        transfer: &SsaTaintTransfer,
        name: &str,
        caps: Cap,
        state: &SsaTaintState,
    ) -> Option<Cap> {
        if !self.anchor_is_outermost() {
            return None;
        }
        let pos = info
            .call
            .arg_uses
            .iter()
            .position(|g| g.iter().any(|u| u == name))?;
        let mut seen = false;
        let mut out = Cap::empty();
        for u in &self.tree.uses {
            if self.anchor_slot(u) != Some(CallSlot::Arg(pos as u16))
                || member_source_caps(transfer, &u.text).is_empty()
            {
                continue;
            }
            seen = true;
            out |= self.occurrence_caps(u, caps, state);
        }
        seen.then_some(out)
    }
}

/// Occurrences recorded for the SSA value `v`, matched by its `var_name`.
fn value_occurrences<'a>(
    tree: &'a NestedCallTree,
    v: SsaValue,
    ssa: &SsaBody,
) -> impl Iterator<Item = &'a NestedUse> + 'a {
    let name = ssa
        .value_defs
        .get(v.0 as usize)
        .and_then(|d| d.var_name.clone());
    tree.uses
        .iter()
        .filter(move |u| name.as_deref() == Some(u.text.as_str()))
}

/// True when every occurrence of `v` lies inside a call satisfying
/// `confines` that is a whole argument of the anchor call
/// (`sink(Integer.toString(n))`, not `sink("x" + Integer.toString(n))`).
/// `None` when the node has no usable record or `v` has no recorded
/// occurrence, so the caller can fall back to its per-position check.
pub(super) fn value_confined_by(
    info: &NodeInfo,
    v: SsaValue,
    ssa: &SsaBody,
    confines: impl Fn(&str) -> bool,
) -> Option<bool> {
    let tree = info.call.nested_calls.as_deref()?;
    let anchor = tree.anchor?;
    let mut any = false;
    for u in value_occurrences(tree, v, ssa) {
        any = true;
        let mut call = u.call;
        let mut hit = false;
        while let Some(c) = call {
            if c == anchor {
                break;
            }
            let node = &tree.calls[c as usize];
            if node.parent == Some(anchor) {
                hit = node.exact_arg && confines(&node.callee);
                break;
            }
            call = node.parent;
        }
        if !hit {
            return Some(false);
        }
    }
    any.then_some(true)
}

/// Collect an entry for each source call nested in a payload argument of
/// the sink call (`exec(getCmd(r))`, `system(getenv("CMD"))`): the source
/// never becomes an SSA value of its own, so without this only its let-bound
/// twin (`c = getCmd(r); exec(c)`) is reported.  The entry rides on the sink
/// op's own value with an origin at the sink node spanning the nested call.
/// Returns whether any entry came from a callee summary.
///
/// Only sources in an argument of the sink call count; a call on the sink's
/// receiver chain is part of the sink expression itself (`fs::read_to_string
/// (p).unwrap()`).  Positions follow the same priority as the tainted-value
/// scan: an explicit payload-position list, then the callee summary's
/// `param_to_sink`, then every argument.  A position whose pre-emitted
/// member-source variable still reaches the sink (it is in `existing`) is
/// skipped, as that argument is already reported through the variable.
/// Callers leave out destination-filtered sinks, whose payload is a set of
/// object fields rather than positions.
#[allow(clippy::too_many_arguments)]
pub(super) fn add_nested_source_values(
    ops: &NestedOperands,
    sink_value: SsaValue,
    sink_node: petgraph::graph::NodeIndex,
    info: &NodeInfo,
    ssa: &SsaBody,
    state: &SsaTaintState,
    sink_caps: Cap,
    positions: Option<&[usize]>,
    param_to_sink: &[(usize, Cap)],
    type_suppressible: bool,
    producer: impl Fn(&str) -> bool,
    existing: &[(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)],
    out: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
) -> bool {
    let mut via_summary = false;
    for src in ops.nested_sources(state, producer) {
        if type_suppressible && src.confined {
            continue;
        }
        let CallSlot::Arg(p) = src.slot else {
            continue;
        };
        let pos = p as usize;
        let synth = |u: &String| u.starts_with(SYNTH_SOURCE_PREFIX);
        let bound = if ops.anchor_is_outermost() {
            // A member-source binding at this position that still reaches
            // the sink already reports the argument.
            info.call.arg_uses.get(pos).is_some_and(|g| {
                g.iter().filter(|u| synth(u)).any(|u| {
                    existing.iter().any(|(v, _, _)| {
                        ssa.value_defs
                            .get(v.0 as usize)
                            .and_then(|d| d.var_name.as_deref())
                            == Some(u.as_str())
                    })
                })
            })
        } else {
            // Pre-emitted positions index the outermost call, not a nested
            // anchor; any binding may stand for this source.
            info.taint.uses.iter().any(synth)
        };
        if bound {
            continue;
        }
        let mut reach = src.caps & sink_caps;
        if let Some(ps) = positions {
            if !ps.contains(&pos) {
                continue;
            }
        } else if !param_to_sink.is_empty() {
            let per_param = param_to_sink
                .iter()
                .filter(|(i, _)| *i == pos)
                .map(|(_, c)| *c)
                .reduce(|a, b| a | b);
            match per_param {
                Some(c) => reach &= c,
                None => continue,
            }
        }
        if reach.is_empty() {
            continue;
        }
        via_summary |= src.via_summary;
        let origin = TaintOrigin {
            node: sink_node,
            source_kind: crate::labels::infer_source_kind(src.caps, src.callee),
            source_span: Some(src.span),
        };
        match out.iter_mut().find(|(v, _, _)| *v == sink_value) {
            Some((_, caps, origins)) => {
                *caps |= src.caps;
                super::push_origin_bounded(origins, origin);
            }
            None => out.push((sink_value, src.caps, SmallVec::from_elem(origin, 1))),
        }
    }
    via_summary
}
