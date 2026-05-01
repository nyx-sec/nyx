#![allow(clippy::collapsible_if)]

use super::domain::{AuthLevel, ChainProxyState, ProductState, ResourceLifecycle};
use super::engine::Transfer;
use super::symbol::{SymbolId, SymbolInterner};
use crate::cfg::{EdgeKind, NodeInfo, StmtKind};
use crate::cfg_analysis::rules::{self, ResourcePair};
use crate::symbol::Lang;
use petgraph::graph::NodeIndex;

/// Decompose a textual callee like `"c.mu.Lock"` into
/// `(chain_receiver_text, method_suffix)`.  Returns `None` when the
/// callee isn't a clean dotted member chain (parens, brackets, `::`,
/// arrow operators, whitespace, or other complex tokens disqualify it).
///
/// Textual mirror of `try_lower_field_proj_chain` in
/// `src/ssa/lower.rs`. The state engine doesn't read SSA bodies, so
/// the parse rules are duplicated. A success here implies a FieldProj
/// chain at SSA level (or a direct receiver for the 1-dot case).
///
/// **Returns** `Some(("c", "Close"))` for `"c.Close"` (1 dot, the
/// receiver is a bare ident); `Some(("c.mu", "Lock"))` for
/// `"c.mu.Lock"` (2 dots, receiver is a 1-element chain);
/// `Some(("c.writer.header", "set"))` for `"c.writer.header.set"`
/// (3 dots, receiver is a 2-element chain).  Returns `None` for any
/// callee shape we can't safely decompose textually.
fn try_chain_decompose(callee: &str) -> Option<(&str, &str)> {
    for ch in callee.chars() {
        match ch {
            '(' | ')' | '[' | ']' | '<' | '>' | '?' | '*' | '&' | ':' | ' ' | '\t' | '\n' | '-'
            | '!' | ',' | ';' | '"' | '\'' | '\\' => return None,
            _ => {}
        }
    }
    let last_dot = callee.rfind('.')?;
    let receiver_text = &callee[..last_dot];
    let method_suffix = &callee[last_dot + 1..];
    if receiver_text.is_empty() || method_suffix.is_empty() {
        return None;
    }
    // Reject if any segment in the receiver is empty (leading dot,
    // double dots), same discipline as the SSA-side helper.
    if receiver_text.split('.').any(str::is_empty) {
        return None;
    }
    Some((receiver_text, method_suffix))
}

/// Events emitted during transfer for illegal state transitions.
/// These are NOT lattice values, they become findings in `facts.rs`.
#[derive(Debug, Clone)]
pub struct TransferEvent {
    pub kind: TransferEventKind,
    pub node: NodeIndex,
    pub var: SymbolId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEventKind {
    UseAfterClose,
    DoubleClose,
}

/// Resource-use patterns: callees that read/write/operate on a resource handle
/// (triggering use-after-close if the handle is closed).
static RESOURCE_USE_PATTERNS: &[&str] = &[
    "read",
    "write",
    "send",
    "recv",
    "fread",
    "fwrite",
    "fgets",
    "fputs",
    "fprintf",
    "fscanf",
    "fflush",
    "fseek",
    "ftell",
    "rewind",
    "feof",
    "ferror",
    "fgetc",
    "fputc",
    "getc",
    "putc",
    "ungetc",
    "query",
    "execute",
    "fetch",
    "sendto",
    "recvfrom",
    "ioctl",
    "fcntl",
    // Memory access functions (for malloc/free use-after-free detection)
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strcmp",
    "strncmp",
    "strlen",
    "sprintf",
    "snprintf",
    // Dot-prefixed method patterns (cross-language method calls)
    ".read",
    ".write",
    ".send",
    ".recv",
    ".query",
    ".execute",
    ".fetch",
    // JS/TS Sync variants (suffix doesn't match plain "read"/"write")
    "readSync",
    "writeSync",
    "readFileSync",
    "writeFileSync",
    "appendFileSync",
    "ftruncateSync",
    "fsyncSync",
    "fstatSync",
    // Stream operations
    "pipe",
    "unpipe",
    "resume",
    "pause",
    "destroy",
];

/// Auth-call matchers for admin-level privilege.
static ADMIN_PATTERNS: &[&str] = &[
    "is_admin",
    "hasrole",
    "has_role",
    "check_admin",
    "require_admin",
];

/// Effect type for resource method summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceEffect {
    Acquire,
    Release,
}

/// Summary for a method body that wraps a known resource operation.
/// Only created for methods whose bodies actually contain a recognized
/// resource acquire/release call from the existing resource_pairs matchers.
#[derive(Debug, Clone)]
pub struct ResourceMethodSummary {
    /// Method name (e.g., "open", "close").
    pub method_name: String,
    /// Whether this method acquires or releases a resource.
    pub effect: ResourceEffect,
    /// `parent_body_id` of the declaring method, groups methods by class.
    pub class_group: crate::cfg::BodyId,
    /// Span of the actual resource operation (e.g., fs.openSync at line 7).
    pub original_span: (usize, usize),
}

pub struct DefaultTransfer<'a> {
    pub lang: Lang,
    pub resource_pairs: &'a [ResourcePair],
    pub interner: &'a SymbolInterner,
    /// Resource method summaries for cross-body proxy resolution.
    pub resource_method_summaries: &'a [ResourceMethodSummary],
    /// Optional per-body field-only points-to hints, names that resolve
    /// to a value whose entire abstract heap identity is one or more
    /// [`crate::pointer::AbsLoc::Field`] locations (e.g. `m := c.mu`).
    ///
    /// Populated only when `NYX_POINTER_ANALYSIS=1` is set and the
    /// state-analysis caller built the body's
    /// [`crate::pointer::PointsToFacts`].  When present, the proxy-acquire
    /// logic routes single-dot calls on field-aliased receivers
    /// (e.g. `m.Lock()` after `m := c.mu`) into `chain_proxies` instead
    /// of marking the local with a `SymbolId` that would later be flagged
    /// as a leak.  Strict-additive: when `None`, behaviour matches the
    /// pointer-unaware fallback exactly.
    pub ptr_proxy_hints:
        Option<&'a std::collections::HashMap<String, crate::pointer::PtrProxyHint>>,
}

impl Transfer<ProductState> for DefaultTransfer<'_> {
    type Event = TransferEvent;

    fn apply(
        &self,
        node_idx: NodeIndex,
        info: &NodeInfo,
        edge: Option<EdgeKind>,
        mut state: ProductState,
    ) -> (ProductState, Vec<TransferEvent>) {
        let mut events = Vec::new();

        match info.kind {
            StmtKind::Call => {
                self.apply_call(node_idx, info, &mut state, &mut events);
            }
            StmtKind::If => {
                self.apply_if(info, edge, &mut state);
            }
            StmtKind::Seq => {
                self.apply_assignment(node_idx, info, &mut state);
            }
            _ => {}
        }

        (state, events)
    }
}

impl DefaultTransfer<'_> {
    /// Look up a variable's [`SymbolId`] using the node's enclosing function
    /// as scope context.  This ensures same-name variables in different
    /// functions resolve to distinct IDs.
    fn get_sym(&self, info: &NodeInfo, name: &str) -> Option<SymbolId> {
        self.interner
            .get_scoped(info.ast.enclosing_func.as_deref(), name)
    }

    /// Returns `true` when the call was fully handled as a
    /// field-aliased receiver proxy and the rest of `apply_call`
    /// should bail. Activates on single-dot calls whose receiver is
    /// `FieldOnly` in the hint map and that match a
    /// [`ResourceMethodSummary`]. The acquire/release effect is
    /// recorded against `state.chain_proxies` keyed by receiver name.
    fn try_apply_field_alias_proxy(
        &self,
        info: &NodeInfo,
        callee: &str,
        state: &mut ProductState,
    ) -> bool {
        let Some(hints) = self.ptr_proxy_hints else {
            return false;
        };
        // Only single-dot callees: `m.Lock`, not `c.mu.Lock` (which the
        // chain-receiver block already handles textually) and not zero-
        // dot (no receiver to alias).
        let Some((receiver_text, method_suffix)) = try_chain_decompose(callee) else {
            return false;
        };
        if receiver_text.contains('.') {
            return false;
        }
        let recv_name: &str = match info.call.receiver.as_deref() {
            Some(r) if !r.contains('.') && !r.contains('(') => r,
            _ => receiver_text,
        };
        if hints.get(recv_name).copied() != Some(crate::pointer::PtrProxyHint::FieldOnly) {
            return false;
        }
        let mut handled = false;
        for summary in self.resource_method_summaries {
            if !summary.method_name.eq_ignore_ascii_case(method_suffix) {
                continue;
            }
            handled = true;
            match summary.effect {
                ResourceEffect::Acquire => {
                    state.chain_proxies.insert(
                        recv_name.to_string(),
                        ChainProxyState {
                            lifecycle: ResourceLifecycle::OPEN,
                            class_group: summary.class_group,
                            acquire_span: summary.original_span,
                        },
                    );
                }
                ResourceEffect::Release => {
                    if let Some(entry) = state.chain_proxies.get_mut(recv_name) {
                        if entry.class_group == summary.class_group
                            && entry.lifecycle.contains(ResourceLifecycle::OPEN)
                        {
                            entry.lifecycle = ResourceLifecycle::CLOSED;
                        }
                    }
                }
            }
        }
        handled
    }

    fn apply_call(
        &self,
        node_idx: NodeIndex,
        info: &NodeInfo,
        state: &mut ProductState,
        events: &mut Vec<TransferEvent>,
    ) {
        let callee = match &info.call.callee {
            Some(c) => c.to_ascii_lowercase(),
            None => return,
        };

        // ── field-aliased receiver fast-path ───────────
        // When the receiver name resolves through points-to to a value
        // whose abstract heap identity is purely `Field(_, _)` (e.g.
        // `m := c.mu` followed by `m.Lock()`), the receiver is a
        // sub-object alias rather than a standalone resource handle.
        // Routing the entire call into `chain_proxies` here, *before*
        // the SymbolId-based direct-acquire/release/proxy branches ,
        // suppresses the FP class where the local `m` would otherwise
        // be flagged as a leakable resource at function exit.
        //
        // Strict-additive: when `ptr_proxy_hints` is `None` or the
        // receiver name is absent from the map, this returns early and
        // the legacy branches run unchanged.
        if self.try_apply_field_alias_proxy(info, &callee, state) {
            return;
        }

        // ── Resource acquire ─────────────────────────────────────────────
        let mut direct_acquire = false;
        for pair in self.resource_pairs {
            let is_acquire = pair.acquire.iter().any(|a| callee_matches(&callee, a));
            let is_excluded = pair
                .exclude_acquire
                .iter()
                .any(|e| callee_matches(&callee, e));

            if is_acquire
                && !is_excluded
                && let Some(ref def) = info.taint.defines
                && let Some(sym) = self.get_sym(info, def)
            {
                state.resource.set(sym, ResourceLifecycle::OPEN);
                direct_acquire = true;
            }
        }

        // ── Resource release ─────────────────────────────────────────────
        // Track which variables have already been released to avoid double-
        // matching across multiple resource pair definitions.
        let mut direct_release = false;
        let mut released: smallvec::SmallVec<[SymbolId; 4]> = smallvec::SmallVec::new();
        for pair in self.resource_pairs {
            let is_release = pair.release.iter().any(|r| callee_matches(&callee, r));
            if is_release {
                direct_release = true;
                // Go `defer f.Close()`: skip the CLOSED transition so the
                // variable stays OPEN mid-function.  Leak suppression is
                // handled separately in extract_findings().
                if info.in_defer {
                    continue;
                }
                for used in &info.taint.uses {
                    if let Some(sym) = self.get_sym(info, used) {
                        if released.contains(&sym) {
                            continue;
                        }
                        let current = state.resource.get(sym);
                        if current == ResourceLifecycle::CLOSED {
                            // Double close
                            events.push(TransferEvent {
                                kind: TransferEventKind::DoubleClose,
                                node: node_idx,
                                var: sym,
                            });
                        } else if current.contains(ResourceLifecycle::OPEN) {
                            state.resource.set(sym, ResourceLifecycle::CLOSED);
                        }
                        released.push(sym);
                    }
                }
            }
        }

        // ── Resource method proxy ────────────────────────────────────────
        // When no direct resource pair matched, check if the callee is a
        // method wrapper for a known resource operation.
        //
        // the previous
        // single-dot band-aid (`callee.matches('.').count() == 1 &&
        // !callee.contains('(')`) silently dropped chained receivers
        // because the original textual extractor took the chain root as
        // receiver, collapsing `c.writer.header().set` to `c` and
        // marking `c` as proxy-acquired (the gin/context.go FP class).
        //
        // The band-aid is now deleted.  Chained-receiver method calls
        // are routed to a *separate* state map (`chain_proxies`) keyed by
        // the joined receiver chain text, so `c.mu.Lock()` acquires
        // `c.mu` (a chain-receiver entity), not `c`.  The chain receiver
        // is independent of the chain root: leaks/double-closes are
        // tracked per chain, never propagated up to the root.
        //
        // The single-dot case (`<recv>.<method>`) keeps the original
        // SymbolId-based path so existing fixtures' lifecycle tracking,
        // leak detection, and finding attribution stay bit-for-bit
        // identical.
        // Chain-receiver proxy path runs independently of the direct
        // acquire/release flags: it touches a *separate* state map
        // (`chain_proxies`) that doesn't overlap with the SymbolId-based
        // `state.resource` / `receiver_class_group` lattice.  This is
        // important for callees like `c.mu.Unlock()` where the textual
        // direct-release matcher (`.Unlock`) fires (sets `direct_release`
        // even without a SymbolId state change), but the chain receiver
        // (`c.mu`) is still the semantically meaningful target.
        if let Some((receiver_text, method_suffix)) = try_chain_decompose(&callee) {
            let receiver_is_chain = receiver_text.contains('.');
            if receiver_is_chain {
                for summary in self.resource_method_summaries {
                    if !summary.method_name.eq_ignore_ascii_case(method_suffix) {
                        continue;
                    }
                    match summary.effect {
                        ResourceEffect::Acquire => {
                            state.chain_proxies.insert(
                                receiver_text.to_string(),
                                ChainProxyState {
                                    lifecycle: ResourceLifecycle::OPEN,
                                    class_group: summary.class_group,
                                    acquire_span: summary.original_span,
                                },
                            );
                        }
                        ResourceEffect::Release => {
                            if let Some(entry) = state.chain_proxies.get_mut(receiver_text) {
                                if entry.class_group == summary.class_group
                                    && entry.lifecycle.contains(ResourceLifecycle::OPEN)
                                {
                                    entry.lifecycle = ResourceLifecycle::CLOSED;
                                }
                            }
                        }
                    }
                }
            } else if !direct_acquire && !direct_release {
                // Single-dot receiver (`<recv>.<method>`): existing
                // SymbolId-based path.  Gated on direct_acquire/release
                // because it shares state with the direct paths above ,
                // running both would double-transition.  Honour the
                // explicit `info.call.receiver` when it's the same bare
                // ident, otherwise fall back to the parsed receiver text.
                let recv_name: &str = match info.call.receiver.as_deref() {
                    Some(r) if !r.contains('.') && !r.contains('(') => r,
                    _ => receiver_text,
                };
                for summary in self.resource_method_summaries {
                    if !summary.method_name.eq_ignore_ascii_case(method_suffix) {
                        continue;
                    }
                    let Some(sym) = self.get_sym(info, recv_name) else {
                        continue;
                    };
                    match summary.effect {
                        ResourceEffect::Acquire => {
                            state.resource.set(sym, ResourceLifecycle::OPEN);
                            state.receiver_class_group.insert(sym, summary.class_group);
                            state.proxy_acquire_spans.insert(sym, summary.original_span);
                        }
                        ResourceEffect::Release => {
                            if state.receiver_class_group.get(&sym) == Some(&summary.class_group) {
                                let current = state.resource.get(sym);
                                if current.contains(ResourceLifecycle::OPEN) {
                                    state.resource.set(sym, ResourceLifecycle::CLOSED);
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Resource use (pair-specific patterns first, then global fallback)
        let mut use_checked = false;
        for pair in self.resource_pairs {
            if pair.use_patterns.iter().any(|p| callee_matches(&callee, p)) {
                use_checked = true;
                for used in &info.taint.uses {
                    if let Some(sym) = self.get_sym(info, used) {
                        if state.resource.get(sym) == ResourceLifecycle::CLOSED {
                            events.push(TransferEvent {
                                kind: TransferEventKind::UseAfterClose,
                                node: node_idx,
                                var: sym,
                            });
                        }
                    }
                }
            }
        }
        if !use_checked {
            let is_use = RESOURCE_USE_PATTERNS
                .iter()
                .any(|p| callee_matches(&callee, p));
            if is_use {
                for used in &info.taint.uses {
                    if let Some(sym) = self.get_sym(info, used) {
                        if state.resource.get(sym) == ResourceLifecycle::CLOSED {
                            events.push(TransferEvent {
                                kind: TransferEventKind::UseAfterClose,
                                node: node_idx,
                                var: sym,
                            });
                        }
                    }
                }
            }
        }

        // ── Auth call ────────────────────────────────────────────────────
        let auth_rules = rules::auth_rules(self.lang);
        let is_auth = auth_rules.iter().any(|rule| {
            rule.matchers
                .iter()
                .any(|m| callee_matches(&callee, &m.to_ascii_lowercase()))
        });
        if is_auth {
            let is_admin = ADMIN_PATTERNS.iter().any(|p| callee_matches(&callee, p));
            let new_level = if is_admin {
                AuthLevel::Admin
            } else {
                AuthLevel::Authed
            };
            if new_level > state.auth.auth_level {
                state.auth.auth_level = new_level;
            }
        }

        // ── Validation call (guard) ──────────────────────────────────────
        if is_guard_like(&callee) {
            for used in &info.taint.uses {
                if let Some(sym) = self.get_sym(info, used) {
                    state.auth.validated.insert(sym);
                }
            }
        }
    }

    fn apply_if(&self, info: &NodeInfo, edge: Option<EdgeKind>, state: &mut ProductState) {
        // Determine the "positive edge", the edge where the underlying
        // (de-negated) condition evaluates to true.
        //
        // For `if (is_authenticated(req))`:  positive = True edge
        // For `if (!allowed[cmd])`:          positive = False edge
        //   (because `!X` being false means `X` is true)
        let is_positive_edge = if info.condition_negated {
            matches!(edge, Some(EdgeKind::False))
        } else {
            matches!(edge, Some(EdgeKind::True))
        };

        // Resource null-check: `if (f)` or `if (!f)` where f is a tracked
        // resource currently in OPEN state.  The "var is falsy" edge means
        // the acquisition returned null/zero, no resource was actually
        // produced, so subsequent close requirements do not apply on that
        // path.  Clearing OPEN suppresses the spurious may-leak finding for
        // the canonical NULL-safe close idiom in C / C++ / similar:
        //
        //     FILE *f = fopen(path, "r");
        //     if (f) fclose(f);
        //
        // Without this rule the false edge keeps OPEN, joins with the true
        // edge's CLOSED at function exit, and produces a may-leak FP even
        // though the code is correct.
        //
        // Heuristic conditions:
        //   * condition is a single-variable truth check (no comparisons,
        //     no calls, `condition_vars.len() == 1` and the trimmed text
        //     equals that variable name).
        //   * the var has OPEN in its lifecycle bitset.
        //   * the edge represents "var is falsy" (= !is_positive_edge).
        if !is_positive_edge && is_simple_truth_check(info) {
            for var in &info.condition_vars {
                if let Some(sym) = self.get_sym(info, var) {
                    let lc = state.resource.get(sym);
                    if lc.contains(ResourceLifecycle::OPEN) {
                        state
                            .resource
                            .set(sym, lc.difference(ResourceLifecycle::OPEN));
                    }
                }
            }
        }

        if !is_positive_edge {
            return;
        }

        if let Some(ref cond) = info.condition_text {
            let cond_lower = cond.to_ascii_lowercase();
            // Strip leading negation operator for pattern matching ,
            // the edge selection above already encodes the semantics.
            let cond_inner = if info.condition_negated {
                cond_lower.trim_start_matches('!').trim_start()
            } else {
                cond_lower.as_str()
            };

            // Auth-related condition
            let auth_rules = rules::auth_rules(self.lang);
            let is_auth_cond = auth_rules.iter().any(|rule| {
                rule.matchers
                    .iter()
                    .any(|m| condition_contains_auth_token(cond_inner, m))
            });
            if is_auth_cond {
                let is_admin = ADMIN_PATTERNS
                    .iter()
                    .any(|p| condition_contains_auth_token(cond_inner, p));
                let new_level = if is_admin {
                    AuthLevel::Admin
                } else {
                    AuthLevel::Authed
                };
                if new_level > state.auth.auth_level {
                    state.auth.auth_level = new_level;
                }
            }

            // Go-specific: map boolean lookup is an allowlist/authorization guard.
            // In Go, `map[string]bool` lookups like `allowed[cmd]` return false
            // for missing keys, making `if allowed[cmd]` a standard allowlist pattern.
            if self.lang == Lang::Go && is_go_map_boolean_guard(cond_inner) {
                if AuthLevel::Authed > state.auth.auth_level {
                    state.auth.auth_level = AuthLevel::Authed;
                }
            }

            // Validation-related condition
            if is_guard_like(cond_inner) {
                for var in &info.condition_vars {
                    if let Some(sym) = self.get_sym(info, var) {
                        state.auth.validated.insert(sym);
                    }
                }
            }
        }
    }

    fn apply_assignment(&self, _node_idx: NodeIndex, info: &NodeInfo, state: &mut ProductState) {
        // Ownership transfer: if `defines` reassigns a tracked resource
        // variable from a `uses` variable, transfer the lifecycle.
        //
        // Skip when the RHS is a function or lambda literal: storing a
        // closure into a property (`ws.onclose = () => { ... }`,
        // `obj.handler = function(){...}`) does not move ownership of the
        // resources the closure body references — those identifiers appear
        // in `info.taint.uses` only because `def_use` walks the literal's
        // body, not because the assignment itself reads them.  Without this
        // gate, the first OPEN-tracked capture inside the closure body gets
        // marked MOVED and the property's symbol becomes the new OPEN
        // owner, which then surfaces as a spurious leak on the property.
        if info.rhs_is_function_literal {
            return;
        }
        if let Some(ref def) = info.taint.defines
            && let Some(def_sym) = self.get_sym(info, def)
        {
            // If the RHS is a tracked resource, transfer its state
            for used in &info.taint.uses {
                if let Some(use_sym) = self.get_sym(info, used) {
                    let lc = state.resource.get(use_sym);
                    if lc.contains(ResourceLifecycle::OPEN) {
                        state.resource.set(def_sym, lc);
                        state.resource.set(use_sym, ResourceLifecycle::MOVED);
                        return;
                    }
                }
            }
        }
    }
}

/// Public wrapper for `callee_matches` used by `build_resource_method_summaries`.
pub fn callee_matches_pub(callee: &str, pattern: &str) -> bool {
    callee_matches(callee, pattern)
}

/// Check if a callee matches a pattern.
/// Supports suffix matching (e.g., "fclose" matches callee "my_fclose")
/// and dot-prefix matching (e.g., ".close" matches "file.close").
fn callee_matches(callee: &str, pattern: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    if pattern_lower.starts_with('.') {
        // Method pattern: ".close" matches "x.close", "file.close", etc.
        callee.ends_with(&pattern_lower)
    } else {
        // Exact or suffix match
        callee == pattern_lower || callee.ends_with(&pattern_lower)
    }
}

/// Check if a callee looks like a guard/validation function.
fn is_guard_like(callee: &str) -> bool {
    static GUARD_PREFIXES: &[&str] = &["validate", "sanitize", "check_", "verify_", "assert_"];
    GUARD_PREFIXES.iter().any(|p| callee.starts_with(p))
}

/// True iff the condition is a single-variable truth check (no comparison,
/// no method call, no boolean composition), the bare `if (f)` or `if (!f)`
/// shape used as a NULL-safe gate around resource access.
///
/// Conservative: requires `condition_vars` to have exactly one entry, and
/// the de-negated `condition_text` to be exactly that variable name (with
/// optional parens stripped).  Rejects `if (f != NULL)`, `if (f.method())`,
/// `if (f && g)`, etc., which are not the simple truth-check idiom and may
/// have different semantics for the false-branch resource state.
fn is_simple_truth_check(info: &NodeInfo) -> bool {
    if info.condition_vars.len() != 1 {
        return false;
    }
    let var = &info.condition_vars[0];
    let Some(text) = info.condition_text.as_deref() else {
        return false;
    };
    let stripped = text.trim();
    let stripped = stripped.trim_start_matches('!').trim();
    let stripped = stripped.trim_matches(|c: char| c == '(' || c == ')').trim();
    stripped == var
}

/// Detect Go `map[string]bool` allowlist lookups used as boolean guards.
///
/// Matches when the entire condition is an index expression of the form
/// `identifier[identifier]` (e.g., `allowed[cmd]`, `whitelist[key]`).
/// In Go, indexing a `map[string]bool` returns `false` for missing keys,
/// making `if allowed[cmd]` a standard allowlist/authorization pattern.
///
/// Narrow by design: does NOT match complex expressions (`arr[i] > 0`),
/// dotted receivers (`obj.map[key]`), or nested indexing.
fn is_go_map_boolean_guard(cond: &str) -> bool {
    let cond = cond.trim();
    let Some(bracket_start) = cond.find('[') else {
        return false;
    };
    if !cond.ends_with(']') {
        return false;
    }
    let before = &cond[..bracket_start];
    let inside = &cond[bracket_start + 1..cond.len() - 1];
    // Before bracket: plain identifier (no dots, no operators)
    // Inside bracket: identifier, possibly dotted (r.URL.Query().Get("cmd"))
    !before.is_empty()
        && before
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !inside.is_empty()
        && inside
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

/// Check if condition text contains an auth/admin matcher at a word boundary.
///
/// Dispatches based on matcher content:
/// - **Identifier-only** (`is_authenticated`, `require_auth`): tokenise condition
///   text on non-identifier characters and require an exact token match.
/// - **Contains punctuation** (`middleware.auth`): find the matcher as a substring
///   and verify word boundaries (non-ident char or string edge) on both sides.
fn condition_contains_auth_token(cond: &str, matcher: &str) -> bool {
    let matcher_lower = matcher.to_ascii_lowercase();
    let is_ident_only = matcher_lower
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_');

    if is_ident_only {
        // Tokenise on non-identifier chars, check for exact token match.
        cond.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|s| !s.is_empty())
            .any(|token| token == matcher_lower)
    } else {
        // Word-boundary substring match for punctuated patterns.
        let hay = cond.as_bytes();
        let needle = matcher_lower.as_bytes();
        if needle.len() > hay.len() {
            return false;
        }
        let mut start = 0;
        while start + needle.len() <= hay.len() {
            if let Some(pos) = cond[start..].find(&*matcher_lower) {
                let abs = start + pos;
                let end = abs + needle.len();
                let left_ok = abs == 0 || {
                    let c = hay[abs - 1];
                    !c.is_ascii_alphanumeric() && c != b'_'
                };
                let right_ok = end >= hay.len() || {
                    let c = hay[end];
                    !c.is_ascii_alphanumeric() && c != b'_'
                };
                if left_ok && right_ok {
                    return true;
                }
                start = abs + 1;
            } else {
                break;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{AstMeta, CallMeta, TaintMeta};
    #[test]
    fn callee_matches_exact() {
        assert!(callee_matches("fopen", "fopen"));
        assert!(!callee_matches("fopen", "fclose"));
    }

    #[test]
    fn callee_matches_suffix() {
        assert!(callee_matches("curlx_fclose", "fclose"));
    }

    #[test]
    fn callee_matches_dot_prefix() {
        assert!(callee_matches("file.close", ".close"));
        assert!(!callee_matches("file.close", ".open"));
    }

    #[test]
    fn callee_matches_js_fd_use_patterns() {
        assert!(callee_matches("fs.readsync", "fs.readSync"));
        assert!(callee_matches("fs.writesync", "fs.writeSync"));
        assert!(!callee_matches("fs.readsync", "fs.writeSync"));
    }

    #[test]
    fn callee_matches_stream_method_patterns() {
        assert!(callee_matches("reader.pipe", ".pipe"));
        assert!(callee_matches("stream.write", ".write"));
        assert!(!callee_matches("readstream", ".read")); // no dot, no match
    }

    #[test]
    fn callee_matches_dot_prefix_no_c_interference() {
        assert!(!callee_matches("fread", ".read"));
        assert!(!callee_matches("fwrite", ".write"));
        assert!(!callee_matches("send", ".send"));
    }

    #[test]
    fn acquire_sets_open() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 10),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("f".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fopen".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let (state, events) =
            transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
        assert!(events.is_empty());
        assert_eq!(state.resource.get(sym_f), ResourceLifecycle::OPEN);
    }

    #[test]
    fn close_after_open_sets_closed() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (10, 20),
                ..Default::default()
            },
            taint: TaintMeta {
                uses: vec!["f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fclose".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let (state, events) = transfer.apply(NodeIndex::new(1), &info, None, state);
        assert!(events.is_empty());
        assert_eq!(state.resource.get(sym_f), ResourceLifecycle::CLOSED);
    }

    #[test]
    fn double_close_emits_event() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::CLOSED);

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (20, 30),
                ..Default::default()
            },
            taint: TaintMeta {
                uses: vec!["f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fclose".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let (_state, events) = transfer.apply(NodeIndex::new(2), &info, None, state);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferEventKind::DoubleClose);
        assert_eq!(events[0].var, sym_f);
    }

    #[test]
    fn use_after_close_emits_event() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::CLOSED);

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (30, 40),
                ..Default::default()
            },
            taint: TaintMeta {
                uses: vec!["f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fread".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let (_state, events) = transfer.apply(NodeIndex::new(3), &info, None, state);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferEventKind::UseAfterClose);
    }

    #[test]
    fn is_guard_like_check() {
        assert!(is_guard_like("validate_input"));
        assert!(is_guard_like("sanitize_html"));
        assert!(is_guard_like("check_permission"));
        assert!(!is_guard_like("open_file"));
    }

    #[test]
    fn is_simple_truth_check_recognises_bare_identifier() {
        let make = |text: &str, vars: Vec<&str>| NodeInfo {
            kind: StmtKind::If,
            ast: AstMeta::default(),
            condition_text: Some(text.to_string()),
            condition_vars: vars.into_iter().map(String::from).collect(),
            ..Default::default()
        };
        // Plain `if (f)` truth check
        assert!(is_simple_truth_check(&make("f", vec!["f"])));
        // Negated form `if (!f)`
        assert!(is_simple_truth_check(&make("!f", vec!["f"])));
        // Parenthesised form `if ((f))`
        assert!(is_simple_truth_check(&make("(f)", vec!["f"])));
        // Negated parenthesised form `if (!(f))`
        assert!(is_simple_truth_check(&make("!(f)", vec!["f"])));
        // Negative: comparison
        assert!(!is_simple_truth_check(&make("f != NULL", vec!["f"])));
        // Negative: method call
        assert!(!is_simple_truth_check(&make("f.is_valid()", vec!["f"])));
        // Negative: composite condition
        assert!(!is_simple_truth_check(&make("f && g", vec!["f", "g"])));
        // Negative: empty vars
        assert!(!is_simple_truth_check(&make("f", vec![])));
    }

    #[test]
    fn null_check_clears_open_on_false_edge() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        let info = NodeInfo {
            kind: StmtKind::If,
            condition_text: Some("f".into()),
            condition_vars: vec!["f".into()],
            condition_negated: false,
            ..Default::default()
        };

        // False edge: f is null → should clear OPEN
        let (state_false, _) = transfer.apply(
            NodeIndex::new(5),
            &info,
            Some(EdgeKind::False),
            state.clone(),
        );
        assert!(
            !state_false
                .resource
                .get(sym_f)
                .contains(ResourceLifecycle::OPEN),
            "OPEN should be cleared on the null edge of `if (f)`"
        );

        // True edge: f is non-null → OPEN preserved
        let (state_true, _) = transfer.apply(
            NodeIndex::new(5),
            &info,
            Some(EdgeKind::True),
            state.clone(),
        );
        assert!(
            state_true
                .resource
                .get(sym_f)
                .contains(ResourceLifecycle::OPEN),
            "OPEN should be preserved on the non-null edge of `if (f)`"
        );
    }

    #[test]
    fn null_check_negated_clears_open_on_true_edge() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        // `if (!f)`, condition_negated=true, true-edge means f is null
        let info = NodeInfo {
            kind: StmtKind::If,
            condition_text: Some("!f".into()),
            condition_vars: vec!["f".into()],
            condition_negated: true,
            ..Default::default()
        };

        let (state_true, _) = transfer.apply(
            NodeIndex::new(5),
            &info,
            Some(EdgeKind::True),
            state.clone(),
        );
        assert!(
            !state_true
                .resource
                .get(sym_f)
                .contains(ResourceLifecycle::OPEN),
            "OPEN should be cleared on the null edge of `if (!f)` (true edge)"
        );

        let (state_false, _) = transfer.apply(
            NodeIndex::new(5),
            &info,
            Some(EdgeKind::False),
            state.clone(),
        );
        assert!(
            state_false
                .resource
                .get(sym_f)
                .contains(ResourceLifecycle::OPEN),
            "OPEN should be preserved on the non-null edge of `if (!f)` (false edge)"
        );
    }

    // ── callee_matches for resource patterns ───────────────────────────

    #[test]
    fn callee_matches_js_end_release() {
        assert!(callee_matches("conn.end", ".end"));
        assert!(callee_matches("pool.end", ".end"));
        assert!(!callee_matches("backend", ".end")); // no dot
    }

    #[test]
    fn callee_matches_go_sql_open() {
        assert!(callee_matches("sql.open", "sql.Open")); // case-insensitive
    }

    #[test]
    fn callee_matches_php_pg() {
        assert!(callee_matches("pg_connect", "pg_connect"));
        assert!(callee_matches("pg_close", "pg_close"));
        assert!(!callee_matches("pg_query", "pg_connect"));
    }

    #[test]
    fn callee_matches_java_prepare_statement() {
        assert!(callee_matches("conn.preparestatement", "prepareStatement"));
        assert!(callee_matches("preparestatement", "prepareStatement"));
    }

    #[test]
    fn callee_matches_websocket() {
        assert!(callee_matches("websocket", "WebSocket"));
    }

    #[test]
    fn callee_matches_mysql_create_connection() {
        assert!(callee_matches(
            "mysql.createconnection",
            "mysql.createConnection"
        ));
    }

    #[test]
    fn callee_matches_finish_release() {
        assert!(callee_matches("http.finish", ".finish"));
        assert!(!callee_matches("finish_setup", ".finish")); // no dot
    }

    // ── condition_contains_auth_token ────────────────────────────────────

    #[test]
    fn auth_token_exact_match() {
        assert!(condition_contains_auth_token(
            "is_authenticated",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token("is_admin", "is_admin"));
        assert!(condition_contains_auth_token(
            "require_auth",
            "require_auth"
        ));
    }

    #[test]
    fn auth_token_dotted_access() {
        assert!(condition_contains_auth_token(
            "req.is_authenticated()",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token(
            "user.is_authenticated == true",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token(
            "req.user.is_authenticated",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token("user.is_admin()", "is_admin"));
    }

    #[test]
    fn auth_token_rejects_substring_regression() {
        // Explicit regression locks for known false positives.
        assert!(!condition_contains_auth_token(
            "not_is_authenticated",
            "is_authenticated"
        ));
        assert!(!condition_contains_auth_token(
            "cached_is_authenticated_flag",
            "is_authenticated"
        ));
        assert!(!condition_contains_auth_token(
            "xis_authenticated",
            "is_authenticated"
        ));
        assert!(!condition_contains_auth_token(
            "this_is_admin_panel",
            "is_admin"
        ));
    }

    #[test]
    fn auth_token_underscore_camel_boundary_cases() {
        // Underscore-joined identifiers are single tokens, must not match interior.
        assert!(!condition_contains_auth_token(
            "req.user_is_authenticated_flag",
            "is_authenticated"
        ));
        // Dot-separated segments ARE separate tokens.
        assert!(condition_contains_auth_token(
            "req.user.is_authenticated",
            "is_authenticated"
        ));
    }

    #[test]
    fn auth_token_dotted_matcher() {
        assert!(condition_contains_auth_token(
            "middleware.auth()",
            "middleware.auth"
        ));
        assert!(condition_contains_auth_token(
            "if middleware.auth(req)",
            "middleware.auth"
        ));
        // Left boundary violation.
        assert!(!condition_contains_auth_token(
            "xmiddleware.auth()",
            "middleware.auth"
        ));
        // Right boundary violation, "middleware.authz" extends past "middleware.auth".
        assert!(!condition_contains_auth_token(
            "middleware.authz()",
            "middleware.auth"
        ));
        // "middleware.auth.check", matcher ends at '.', which is non-ident → matches.
        assert!(condition_contains_auth_token(
            "middleware.auth.check()",
            "middleware.auth"
        ));
    }

    // ── condition_contains_auth_token for auth patterns ────────────────

    #[test]
    fn auth_token_jwt_verify() {
        assert!(condition_contains_auth_token(
            "jwt.verify(token)",
            "jwt.verify"
        ));
        assert!(!condition_contains_auth_token(
            "jwt.verifyAsync(token)",
            "jwt.verify"
        ));
    }

    #[test]
    fn auth_token_passport() {
        assert!(condition_contains_auth_token(
            "passport.authenticate('local')",
            "passport.authenticate"
        ));
    }

    #[test]
    fn auth_token_generate_not_auth() {
        assert!(!condition_contains_auth_token(
            "generateToken(secret)",
            "verify_token"
        ));
        assert!(!condition_contains_auth_token(
            "generateToken(secret)",
            "validate_token"
        ));
        assert!(!condition_contains_auth_token(
            "generateToken(secret)",
            "authenticate"
        ));
    }

    #[test]
    fn auth_token_ensure_authenticated() {
        // condition_contains_auth_token expects pre-lowered condition text
        assert!(condition_contains_auth_token(
            "ensureauthenticated(req)",
            "ensureAuthenticated"
        ));
    }

    #[test]
    fn auth_token_require_role_not_substring() {
        assert!(condition_contains_auth_token(
            "requirerole('admin')",
            "requireRole"
        ));
        assert!(!condition_contains_auth_token(
            "prerequirerole()",
            "requireRole"
        ));
    }

    #[test]
    fn auth_token_boolean_composition() {
        // Compound conditions, each token should be individually matchable.
        assert!(condition_contains_auth_token(
            "is_authenticated && is_admin",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token(
            "is_authenticated && is_admin",
            "is_admin"
        ));
        assert!(condition_contains_auth_token(
            "!is_authenticated && is_admin",
            "is_authenticated"
        ));
        assert!(condition_contains_auth_token(
            "user == null || !user.is_authenticated",
            "is_authenticated"
        ));
    }

    // ─────────────────────────────────────────────────────────────────
    // chain-receiver decomposition + chain_proxies tracking
    // ─────────────────────────────────────────────────────────────────
    //
    // These tests pin the contract that:
    //   1. `try_chain_decompose` parses dotted callees into receiver +
    //      method, bailing on complex tokens.
    //   2. The proxy-method routing in `apply_call` records chained
    //      receivers in `state.chain_proxies` (keyed by joined chain
    //      text), independent from the chain root's `SymbolId`-based
    //      `state.receiver_class_group` entries.
    //   3. Single-dot callees still flow through the existing SymbolId
    //      path (regression guard).
    //   4. The deleted single-dot band-aid no longer suppresses chain
    //      cases, `c.mu.Lock()` now fires the chain-proxies path
    //      instead of being silently dropped.

    #[test]
    fn try_chain_decompose_basic_two_dots() {
        // `c.mu.Lock` → receiver "c.mu", method "Lock".  The receiver
        // is a 1-element chain (one FieldProj at the SSA level).
        let (recv, method) = try_chain_decompose("c.mu.Lock").unwrap();
        assert_eq!(recv, "c.mu");
        assert_eq!(method, "Lock");
    }

    #[test]
    fn try_chain_decompose_three_dots() {
        // `c.writer.header.set` → receiver "c.writer.header", method "set".
        let (recv, method) = try_chain_decompose("c.writer.header.set").unwrap();
        assert_eq!(recv, "c.writer.header");
        assert_eq!(method, "set");
    }

    #[test]
    fn try_chain_decompose_one_dot_keeps_bare_receiver() {
        // `f.Close` → receiver "f" (bare ident), method "Close".  The
        // single-dot case still decomposes; apply_call routes it through
        // the existing SymbolId-based path (not chain_proxies).
        let (recv, method) = try_chain_decompose("f.Close").unwrap();
        assert_eq!(recv, "f");
        assert_eq!(method, "Close");
    }

    #[test]
    fn try_chain_decompose_no_dot_returns_none() {
        assert!(try_chain_decompose("Close").is_none());
        assert!(try_chain_decompose("fopen").is_none());
    }

    #[test]
    fn try_chain_decompose_complex_tokens_returns_none() {
        // Each of these contains a token signaling complexity that breaks
        // the simple `<ident>.<ident>...` shape; helper must bail to
        // preserve the conservative behaviour the band-aid established.
        for s in [
            "Foo::bar::baz",     // Rust path, `::` rules it out
            "ptr->field.f",      // C arrow operator
            "obj.f().g",         // intermediate call
            "vec[0].field",      // index expression
            "obj?.f.g",          // optional chain
            "obj.f g",           // whitespace
            "c.writer.header()", // trailing parens (the gin/context shape)
        ] {
            assert!(
                try_chain_decompose(s).is_none(),
                "expected bail on complex callee {s}"
            );
        }
    }

    #[test]
    fn try_chain_decompose_rejects_empty_segments() {
        for s in [".x.f", "x..f", "x.f.", "."] {
            assert!(try_chain_decompose(s).is_none(), "expected bail on {s}");
        }
    }

    #[test]
    fn chain_proxy_acquire_records_chain_text_not_root() {
        // Key behaviour: a chained-receiver acquire (`c.mu.Lock()`)
        // records `c.mu` in `state.chain_proxies` and DOES NOT touch the
        // SymbolId-keyed `receiver_class_group` for the chain root `c`.
        let mut interner = SymbolInterner::new();
        let _sym_c = interner.intern_scoped(None, "c");

        let lock = ResourceMethodSummary {
            method_name: "Lock".into(),
            effect: ResourceEffect::Acquire,
            class_group: crate::cfg::BodyId(7),
            original_span: (10, 20),
        };

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: std::slice::from_ref(&lock),
            ptr_proxy_hints: None,
        };

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 30),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some("c.mu.Lock".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let (state, events) =
            transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
        assert!(events.is_empty());

        // chain_proxies has the chain text entry.
        assert!(
            state.chain_proxies.contains_key("c.mu"),
            "expected chain_proxies['c.mu'] entry; got {:?}",
            state.chain_proxies.keys().collect::<Vec<_>>()
        );
        let entry = &state.chain_proxies["c.mu"];
        assert_eq!(entry.lifecycle, ResourceLifecycle::OPEN);
        assert_eq!(entry.class_group, crate::cfg::BodyId(7));
        assert_eq!(entry.acquire_span, (10, 20));

        // Root `c` is NOT marked in receiver_class_group, the gin/context FP
        // the band-aid was guarding against can no longer reappear.
        assert!(
            state.receiver_class_group.is_empty(),
            "chain root must not inherit proxy state; receiver_class_group was {:?}",
            state.receiver_class_group
        );
    }

    #[test]
    fn chain_proxy_release_after_acquire_transitions_to_closed() {
        // Acquire + matching Release on the same chain receiver +
        // class group should transition the chain entry to CLOSED.
        let mut interner = SymbolInterner::new();
        let _sym_c = interner.intern_scoped(None, "c");
        let class_group = crate::cfg::BodyId(11);

        let summaries = vec![
            ResourceMethodSummary {
                method_name: "Lock".into(),
                effect: ResourceEffect::Acquire,
                class_group,
                original_span: (0, 10),
            },
            ResourceMethodSummary {
                method_name: "Unlock".into(),
                effect: ResourceEffect::Release,
                class_group,
                original_span: (20, 30),
            },
        ];

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: &summaries,
            ptr_proxy_hints: None,
        };

        let lock_info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 10),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some("c.mu.Lock".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) =
            transfer.apply(NodeIndex::new(0), &lock_info, None, ProductState::initial());
        assert_eq!(
            state.chain_proxies["c.mu"].lifecycle,
            ResourceLifecycle::OPEN
        );

        let unlock_info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (20, 30),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some("c.mu.Unlock".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) = transfer.apply(NodeIndex::new(1), &unlock_info, None, state);
        assert_eq!(
            state.chain_proxies["c.mu"].lifecycle,
            ResourceLifecycle::CLOSED
        );
    }

    #[test]
    fn chain_proxy_distinct_chains_dont_collide() {
        // `c.mu.Lock()` and `c.other.Lock()` are independent chain
        // receivers, each gets its own entry in chain_proxies.
        let interner = SymbolInterner::new();
        let class_group = crate::cfg::BodyId(3);

        let lock = ResourceMethodSummary {
            method_name: "Lock".into(),
            effect: ResourceEffect::Acquire,
            class_group,
            original_span: (0, 0),
        };
        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: std::slice::from_ref(&lock),
            ptr_proxy_hints: None,
        };

        let mk_call = |callee: &str| NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 0),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some(callee.into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) = transfer.apply(
            NodeIndex::new(0),
            &mk_call("c.mu.Lock"),
            None,
            ProductState::initial(),
        );
        let (state, _) = transfer.apply(NodeIndex::new(1), &mk_call("c.other.Lock"), None, state);
        assert!(state.chain_proxies.contains_key("c.mu"));
        assert!(state.chain_proxies.contains_key("c.other"));
        assert_eq!(state.chain_proxies.len(), 2);
    }

    #[test]
    fn single_dot_proxy_acquire_uses_symbol_id_path() {
        // REGRESSION: single-dot callees keep the existing SymbolId-based
        // path, `f.acquireMine()` records against
        // `receiver_class_group[sym_f]`, NOT `chain_proxies["f"]`.  This
        // preserves all existing 1-dot proxy semantics (leak detection,
        // finding attribution).
        //
        // We use an unusual method name so the direct-pair matcher
        // doesn't fire first (Go's resource_pairs cover `.Close`,
        // `.close`, etc., which would short-circuit before the proxy
        // routing).
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern_scoped(None, "f");
        let class_group = crate::cfg::BodyId(2);

        let acquire = ResourceMethodSummary {
            method_name: "acquireMine".into(),
            effect: ResourceEffect::Acquire,
            class_group,
            original_span: (0, 0),
        };
        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: std::slice::from_ref(&acquire),
            ptr_proxy_hints: None,
        };
        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 0),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some("f.acquireMine".into()),
                receiver: Some("f".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) = transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());

        // SymbolId path fired: receiver_class_group has the SymbolId entry.
        assert_eq!(
            state.receiver_class_group.get(&sym_f),
            Some(&class_group),
            "single-dot must use SymbolId path"
        );
        // chain_proxies stays empty: this is NOT a chain receiver.
        assert!(
            state.chain_proxies.is_empty(),
            "single-dot must not populate chain_proxies; got {:?}",
            state.chain_proxies.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn complex_callee_does_not_record_proxy() {
        // REGRESSION: callees with parens / `::` / `[` / `?` are
        // unparseable as chain receivers.  The helper bails, no proxy
        // entry is recorded anywhere.  Matches the conservative behaviour
        // the band-aid established.
        let interner = SymbolInterner::new();
        let class_group = crate::cfg::BodyId(0);
        let lock = ResourceMethodSummary {
            method_name: "Lock".into(),
            effect: ResourceEffect::Acquire,
            class_group,
            original_span: (0, 0),
        };
        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: std::slice::from_ref(&lock),
            ptr_proxy_hints: None,
        };
        for callee in ["c.writer.header().Lock", "Foo::bar::Lock", "c[i].mu.Lock"] {
            let info = NodeInfo {
                kind: StmtKind::Call,
                ast: AstMeta {
                    span: (0, 0),
                    ..Default::default()
                },
                taint: TaintMeta::default(),
                call: CallMeta {
                    callee: Some(callee.into()),
                    ..Default::default()
                },
                ..Default::default()
            };
            let (state, _) =
                transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
            assert!(
                state.chain_proxies.is_empty() && state.receiver_class_group.is_empty(),
                "complex callee {callee} should not record any proxy state; chain={:?} root={:?}",
                state.chain_proxies.keys().collect::<Vec<_>>(),
                state.receiver_class_group.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn chain_proxy_lattice_join_unions_keys() {
        // Sanity check: the lattice join unions chain_proxies keys.
        // Branch A: `c.mu` OPEN.  Branch B: `c.other` OPEN.  Join must
        // contain both, this is the dataflow-correctness invariant
        // for chain tracking across branches.
        use crate::state::lattice::Lattice;
        let mut a = ProductState::initial();
        let mut b = ProductState::initial();
        a.chain_proxies.insert(
            "c.mu".into(),
            ChainProxyState {
                lifecycle: ResourceLifecycle::OPEN,
                class_group: crate::cfg::BodyId(1),
                acquire_span: (0, 0),
            },
        );
        b.chain_proxies.insert(
            "c.other".into(),
            ChainProxyState {
                lifecycle: ResourceLifecycle::OPEN,
                class_group: crate::cfg::BodyId(2),
                acquire_span: (10, 20),
            },
        );
        let joined = a.join(&b);
        assert_eq!(joined.chain_proxies.len(), 2);
        assert!(joined.chain_proxies.contains_key("c.mu"));
        assert!(joined.chain_proxies.contains_key("c.other"));
    }

    #[test]
    fn chain_proxy_lattice_join_merges_lifecycle() {
        // Same chain key on two branches, the lifecycle is OR-joined
        // (OPEN ∪ CLOSED).  Mirrors the `ResourceLifecycle::join`
        // bitflag-or semantics already used for SymbolId-based tracking.
        use crate::state::lattice::Lattice;
        let mut a = ProductState::initial();
        let mut b = ProductState::initial();
        a.chain_proxies.insert(
            "c.mu".into(),
            ChainProxyState {
                lifecycle: ResourceLifecycle::OPEN,
                class_group: crate::cfg::BodyId(1),
                acquire_span: (0, 0),
            },
        );
        b.chain_proxies.insert(
            "c.mu".into(),
            ChainProxyState {
                lifecycle: ResourceLifecycle::CLOSED,
                class_group: crate::cfg::BodyId(1),
                acquire_span: (0, 0),
            },
        );
        let joined = a.join(&b);
        assert_eq!(joined.chain_proxies.len(), 1);
        let lc = joined.chain_proxies["c.mu"].lifecycle;
        assert!(lc.contains(ResourceLifecycle::OPEN));
        assert!(lc.contains(ResourceLifecycle::CLOSED));
    }

    // ─────────────────────────────────────────────────────────────────
    // Pointer-analysis: PtrProxyHint::FieldOnly routes
    // single-dot proxy-acquire to chain_proxies, suppressing the
    // SymbolId path that would otherwise mark the field-aliased local
    // as a leakable resource.
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn field_only_hint_routes_single_dot_acquire_to_chain_proxies() {
        // Models `m := c.mu; m.Lock()`, `m`'s pt set is `{Field(SelfParam, mu)}`,
        // so PtrProxyHint::FieldOnly applies.  The acquire must record
        // `m` in chain_proxies, NOT in receiver_class_group, so the
        // leak detector does not later flag `m` as an OPEN-at-exit
        // resource (it lives inside the function and never escapes).
        let mut interner = SymbolInterner::new();
        let _sym_m = interner.intern_scoped(None, "m");
        let class_group = crate::cfg::BodyId(2);

        let acquire = ResourceMethodSummary {
            method_name: "Lock".into(),
            effect: ResourceEffect::Acquire,
            class_group,
            original_span: (0, 10),
        };

        let mut hints = std::collections::HashMap::new();
        hints.insert("m".to_string(), crate::pointer::PtrProxyHint::FieldOnly);

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: std::slice::from_ref(&acquire),
            ptr_proxy_hints: Some(&hints),
        };

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 10),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some("m.Lock".into()),
                receiver: Some("m".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, events) =
            transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
        assert!(events.is_empty());
        assert!(
            state.chain_proxies.contains_key("m"),
            "FieldOnly hint should route `m.Lock()` into chain_proxies; got {:?}",
            state.chain_proxies.keys().collect::<Vec<_>>()
        );
        assert!(
            state.receiver_class_group.is_empty(),
            "FieldOnly hint must not record SymbolId proxy entry; got {:?}",
            state.receiver_class_group.keys().collect::<Vec<_>>()
        );
        let entry = &state.chain_proxies["m"];
        assert_eq!(entry.lifecycle, ResourceLifecycle::OPEN);
        assert_eq!(entry.class_group, class_group);
    }

    #[test]
    fn field_only_hint_release_transitions_chain_entry_to_closed() {
        // Acquire + Release pair on the field-aliased local both route
        // through chain_proxies, the entry transitions OPEN → CLOSED
        // exactly as the existing chain-receiver path does.
        let mut interner = SymbolInterner::new();
        let _sym_m = interner.intern_scoped(None, "m");
        let class_group = crate::cfg::BodyId(11);

        let summaries = vec![
            ResourceMethodSummary {
                method_name: "Lock".into(),
                effect: ResourceEffect::Acquire,
                class_group,
                original_span: (0, 10),
            },
            ResourceMethodSummary {
                method_name: "Unlock".into(),
                effect: ResourceEffect::Release,
                class_group,
                original_span: (20, 30),
            },
        ];

        let mut hints = std::collections::HashMap::new();
        hints.insert("m".to_string(), crate::pointer::PtrProxyHint::FieldOnly);

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: &summaries,
            ptr_proxy_hints: Some(&hints),
        };

        let lock_info = NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some("m.Lock".into()),
                receiver: Some("m".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) =
            transfer.apply(NodeIndex::new(0), &lock_info, None, ProductState::initial());
        assert_eq!(state.chain_proxies["m"].lifecycle, ResourceLifecycle::OPEN);

        let unlock_info = NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some("m.Unlock".into()),
                receiver: Some("m".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) = transfer.apply(NodeIndex::new(1), &unlock_info, None, state);
        assert_eq!(
            state.chain_proxies["m"].lifecycle,
            ResourceLifecycle::CLOSED
        );
    }

    #[test]
    fn no_hint_falls_through_to_existing_symbol_id_path() {
        // REGRESSION: when `ptr_proxy_hints` is `None`, the single-dot
        // proxy-acquire branch behaves exactly as today, the SymbolId
        // path fires, `chain_proxies` stays empty.  Strict-additive
        // contract: pointer analysis disabled ⇒ no behavioural change.
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern_scoped(None, "f");
        let class_group = crate::cfg::BodyId(3);

        let acquire = ResourceMethodSummary {
            method_name: "acquireMine".into(),
            effect: ResourceEffect::Acquire,
            class_group,
            original_span: (0, 0),
        };
        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: std::slice::from_ref(&acquire),
            ptr_proxy_hints: None,
        };
        let info = NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some("f.acquireMine".into()),
                receiver: Some("f".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) = transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
        assert_eq!(
            state.receiver_class_group.get(&sym_f),
            Some(&class_group),
            "no hint ⇒ SymbolId path"
        );
        assert!(state.chain_proxies.is_empty());
    }

    #[test]
    fn empty_hint_map_does_not_redirect() {
        // REGRESSION: an empty hint map means "every name resolves to
        // PtrProxyHint::Other".  The single-dot branch must fall
        // through to the SymbolId path, not silently route to
        // chain_proxies because the map happened to be empty.
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern_scoped(None, "f");
        let class_group = crate::cfg::BodyId(3);
        let acquire = ResourceMethodSummary {
            method_name: "acquireMine".into(),
            effect: ResourceEffect::Acquire,
            class_group,
            original_span: (0, 0),
        };
        let hints: std::collections::HashMap<String, crate::pointer::PtrProxyHint> =
            std::collections::HashMap::new();
        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: std::slice::from_ref(&acquire),
            ptr_proxy_hints: Some(&hints),
        };
        let info = NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some("f.acquireMine".into()),
                receiver: Some("f".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) = transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
        assert_eq!(state.receiver_class_group.get(&sym_f), Some(&class_group));
        assert!(state.chain_proxies.is_empty());
    }
}
