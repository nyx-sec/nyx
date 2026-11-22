//! `DefaultTransfer`: resource-lifecycle and auth-state transfer function for
//! the generic monotone dataflow engine (separate from taint).
//!
//! Tracks `ResourceLifecycle`, `AuthLevel`, and chain-proxy/product state to
//! detect leaks, use-after-close, double-close, and auth-state issues.

use super::domain::{AuthLevel, ChainProxyState, ProductState, ResourceLifecycle};
use super::engine::Transfer;
use super::symbol::{SymbolId, SymbolInterner};
use crate::cfg::{CalleeNesting, EdgeKind, NodeInfo, RhsShape, StmtKind};
use crate::cfg_analysis::rules::{self, ResourcePair};
use crate::symbol::Lang;
use petgraph::graph::NodeIndex;

/// Whether an acquire whose destination `def` is a struct-field / object-property
/// LHS should be treated as ownership-transfer to the containing object and thus
/// NOT tracked as a function-local resource.  A resource written directly into a
/// member-access LHS is owned by the containing struct/object, whose lifetime the
/// local body cannot observe — it is released in a paired destructor / `Stop()` /
/// `free_*()` method, or transferred to the caller when the object is a parameter.
/// Tracking the field as a local handle is a guaranteed leak FP at function exit.
///
/// Real-repo shapes this covers (RHS is a call, so this is the `apply_call`
/// sibling of the `apply_assignment` field-LHS gate that handles the RHS-is-a-var
/// downstream store):
///   - C:   `c->connect_timeout = hi_malloc(...)` (redis/hiredis net.c),
///     `s->buf = malloc(size)` (redis lua strbuf.c), `pq->items = calloc(...)`.
///   - Go:  `b.cpuprof = os.Create(...)` (prometheus tsdb.go::startProfiling).
///
/// Language policy:
///   - C / C++: `.` (struct value member) OR `->` (pointer member).  A C++
///     `this->fd = fopen(...)` is owned by the object's destructor (RAII), so the
///     arrow form is suppressed exactly like the C struct case.
///   - Go: `.` (struct field).
///   - JS / TS (and all others): NOT suppressed — the class-field acquire
///     `this.fd = fs.openSync(...)` IS the expected leak pattern the TS state
///     fixtures rely on (`tests/fixtures/.../typescript/state/resource_class.ts`).
pub(crate) fn acquire_into_field_transfers_ownership(lang: Lang, def: &str) -> bool {
    match lang {
        Lang::C | Lang::Cpp => def.contains("->") || def.contains('.'),
        Lang::Go => def.contains('.'),
        _ => false,
    }
}

/// Decompose a field-LHS define `"c.buf"` into its single-identifier
/// container base `"c"`.  Returns `None` for shapes that are NOT a plain
/// value-struct member on a bare identifier:
///   - pointer member (`c->buf`) — the container is a pointer, whose
///     pointee lives on the heap or in the caller; ownership escapes.
///   - subscript (`arr[i].buf`) — array element, container decays to a
///     pointer when passed and is hard to prove local.
///   - sub-object (`c.inner.buf`) — the container `c.inner` is itself a
///     field, not a bare stack local.
///   - non-identifier base.
fn single_ident_dot_container(def: &str) -> Option<&str> {
    if def.contains("->") || def.contains('[') || def.contains(']') {
        return None;
    }
    let dot = def.find('.')?;
    let base = &def[..dot];
    let field = &def[dot + 1..];
    if base.is_empty() || field.is_empty() || field.contains('.') {
        return None;
    }
    let mut chars = base.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if !first_ok || !base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(base)
}

/// Container-escape analysis for the struct-field-acquire ownership-transfer
/// suppression (C/C++ only).
///
/// The blanket [`acquire_into_field_transfers_ownership`] gate suppresses
/// EVERY `c.buf = malloc(...)` acquire on the theory that a struct field is
/// owned by its container (released in a paired destructor / by the caller
/// when the container is a parameter).  That is correct when the container
/// escapes the function — but a false negative for a genuinely non-escaping
/// STACK struct: `struct Ctx c; c.buf = malloc(10);` where `c` dies at
/// function exit and `c.buf` is never freed is a real leak.
///
/// This returns the set of single-identifier value-struct container base
/// names (`c`) whose field-acquire provably does NOT transfer ownership,
/// so the caller can lift the suppression for those (and only those)
/// containers.  A container qualifies iff, within this single-body CFG:
///   1. it is DECLARED locally as a value struct — there is a node
///      `struct Ctx c;` (`Seq`, no callee, `defines=None`, `uses=["c"]`)
///      or `struct Ctx c = {…};` (`Seq`, no callee, `defines=Some("c")`,
///      `uses` empty).  A parameter or a global has no such body decl, so
///      requiring one excludes both (a parameter's struct is caller-owned;
///      a global's field allocation is program-lifetime state, not a leak).
///   2. it NEVER escapes — the bare identifier `c` appears in NO other
///      node's `uses` or `arg_uses`.  That covers being passed to a call
///      (`foo(c)`), address-taken (`init(&c)` surfaces bare `c` in
///      `arg_uses`), stored (`x = c`), returned (`return c`), or having a
///      field read out and passed (`log_it(c.tag)` surfaces bare `c`,
///      treated conservatively as an escape).
///
/// Conservative toward SUPPRESSION: any container reference we cannot rule
/// out keeps `c` OUT of the result, so the pre-existing ownership-transfer
/// suppression stands and no field-acquire FP (the redis/git cluster from
/// session-0049) can be re-introduced.  The analysis only ever ADDS a leak
/// for a provably-dead local value struct.  Empty for non-C/C++.
pub(crate) fn nonescaping_local_field_containers(
    cfg: &crate::cfg::Cfg,
    lang: Lang,
) -> std::collections::HashSet<String> {
    let mut result = std::collections::HashSet::new();
    if !matches!(lang, Lang::C | Lang::Cpp) {
        return result;
    }

    // 1. Candidate container bases: single-ident DOT-form field defines.
    let mut candidates: std::collections::HashSet<String> = std::collections::HashSet::new();
    for info in cfg.node_weights() {
        if let Some(def) = info.taint.defines.as_deref()
            && let Some(base) = single_ident_dot_container(def)
        {
            candidates.insert(base.to_string());
        }
    }
    if candidates.is_empty() {
        return result;
    }

    // 2. Each candidate: require a local value-struct decl + prove non-escape.
    for cand in &candidates {
        let mut has_decl = false;
        let mut escapes = false;
        for info in cfg.node_weights() {
            let is_decl = info.kind == StmtKind::Seq
                && info.call.callee.is_none()
                && ((info.taint.defines.is_none()
                    && info.taint.uses.len() == 1
                    && info.taint.uses[0] == *cand)
                    || (info.taint.defines.as_deref() == Some(cand.as_str())
                        && info.taint.uses.is_empty()));
            if is_decl {
                has_decl = true;
                continue; // the decl node's own bare-`c` mention is not an escape
            }
            let bare_in_uses = info.taint.uses.iter().any(|u| u == cand);
            let bare_in_args = info
                .call
                .arg_uses
                .iter()
                .any(|arg| arg.iter().any(|u| u == cand));
            if bare_in_uses || bare_in_args {
                escapes = true;
                break;
            }
        }
        if has_decl && !escapes {
            result.insert(cand.clone());
        }
    }
    result
}

/// True when `def` is a field-acquire (`c.buf`) whose container base `c` is
/// in the provably-non-escaping-local set — the ownership-transfer
/// suppression must be LIFTED (the acquire genuinely leaks).
pub(crate) fn field_container_is_nonescaping(
    nonescaping: &std::collections::HashSet<String>,
    def: &str,
) -> bool {
    single_ident_dot_container(def).is_some_and(|base| nonescaping.contains(base))
}

/// Whether a Return node (or a Ruby tail expression) hands the variable
/// picked out by `is_var` to the caller.
///
/// The structural answer is [`NodeInfo::returned_idents`]: the variable sits
/// in an escape position of the returned value (`return f`, `return f, nil`,
/// `return &W{f: f}`, `return new Wrapper(r)`), while `return f.read()` or
/// `return io.ReadAll(f)` keeps the handle here.
///
/// C / C++ also count any mention in the returned expression.  There, a
/// pointer passed to the call whose result is returned is usually handed on
/// (`return insert(t, node)`, `return register_graft(r, graft)`,
/// `return read_header_fd(fd, ..)` which returns `fd`, `return &x->base`),
/// and the leak passes have no model of what the callee keeps.
pub(crate) fn return_hands_off(lang: Lang, info: &NodeInfo, is_var: impl Fn(&str) -> bool) -> bool {
    if !(info.kind == StmtKind::Return || info.implicit_return) {
        return false;
    }
    info.returned_idents.iter().any(|n| is_var(n))
        || (matches!(lang, Lang::C | Lang::Cpp) && info.taint.uses.iter().any(|n| is_var(n)))
}

/// Method names that store their argument in the receiving collection, so a
/// handle passed to them now belongs to that collection: `list.add(s)`,
/// `map.put(k, s)`, `v.push_back(f)`, `xs.append(f)`, `arr.push(fd)`,
/// `cache.set(k, fd)`, and the synthetic `__index_set__` of `m[k] = f`.
/// Compared case-insensitively against the callee's last segment.
static CONTAINER_INSERT_LEAVES: &[&str] = &[
    "add",
    "addfirst",
    "addlast",
    "append",
    "emplace",
    "emplace_back",
    "emplace_front",
    "insert",
    "offer",
    "push",
    "push_back",
    "push_front",
    "put",
    "putifabsent",
    "set",
    "unshift",
];

/// Argument positions whose bare-variable value a call hands over to a
/// container (or, for C++ `ptr.reset(raw)`, to an owning smart pointer).
/// Empty for every other call.  Only bare identifiers qualify: a nested call
/// or expression argument (`v.push_back(f->next)`) moves nothing.
///
/// Recall trade-off, matching the field-store rule: a handle put into a
/// local collection that then dies unreleased is no longer reported.
pub(crate) fn container_insert_arg_positions(
    lang: Lang,
    info: &NodeInfo,
) -> smallvec::SmallVec<[usize; 2]> {
    let mut out = smallvec::SmallVec::new();
    let Some(callee) = info.call.callee.as_deref() else {
        return out;
    };
    let is_method = callee.contains(['.', ':', '>']);
    let leaf = callee
        .rsplit(['.', ':', '>'])
        .next()
        .unwrap_or(callee)
        .to_ascii_lowercase();
    let first = match (lang, leaf.as_str()) {
        (_, "__index_set__") => 1,
        (Lang::Go, "append") if !is_method => 1,
        (Lang::Php, "array_push" | "array_unshift") if !is_method => 1,
        (Lang::Cpp, "reset") if is_method => 0,
        // Node `stream.pipeline(a, b, .., cb)` destroys every stream on error
        // or completion, so each stream argument is handed over.  `.pipe()`
        // is not: it leaves the destination open when the source errors.
        (Lang::JavaScript | Lang::TypeScript, "pipeline") => 0,
        (_, l) if is_method && CONTAINER_INSERT_LEAVES.contains(&l) => 0,
        _ => return out,
    };
    let args = &info.call.arg_uses;
    if leaf == "set" && args.len() < 2 {
        return out;
    }
    for (i, arg) in args.iter().enumerate().skip(first) {
        let bare = info.arg_callees.get(i).is_none_or(|c| c.is_none()) && arg.len() == 1;
        if bare {
            out.push(i);
        }
    }
    out
}

/// Java wrapper-handoff facts for one body (see `closeable_wrapper_names`).
#[derive(Debug, Default)]
pub struct CloseableWrappers {
    /// Wrapper objects whose lifetime the body accounts for.
    pub names: std::collections::HashSet<String>,
    /// Names bound by a try-with-resources acquire.  That scope already
    /// closes the stream, so a wrapper built on it does not take it over.
    pub managed: std::collections::HashSet<String>,
}

/// Java: names of local wrapper objects whose lifetime is accounted for in
/// this body: closed (`w.close()`, including a release in argument
/// position), returned, bound by try-with-resources, or stored somewhere
/// the function does not own (a field, global, or collection).  A stream
/// passed to the constructor of such a wrapper is owned by the wrapper.
/// Empty for other languages.
pub(crate) fn closeable_wrapper_names(cfg: &crate::cfg::Cfg, lang: Lang) -> CloseableWrappers {
    let mut facts = CloseableWrappers::default();
    if lang != Lang::Java {
        return facts;
    }
    let out = &mut facts.names;
    let pairs = rules::resource_pairs(lang);
    let is_release = |callee: &str| {
        let c = callee.to_ascii_lowercase();
        pairs
            .iter()
            .any(|p| p.release.iter().any(|r| callee_matches(&c, r)))
    };
    for info in cfg.node_weights() {
        if info.kind == StmtKind::Call
            && let Some(callee) = info.call.callee.as_deref()
            && is_release(callee)
            && let Some((recv, _)) = try_chain_decompose(callee)
            && !recv.contains('.')
        {
            out.insert(recv.to_string());
        }
        for arg_callee in info.arg_callees.iter().flatten() {
            if is_release(arg_callee)
                && let Some((recv, _)) = try_chain_decompose(arg_callee)
                && !recv.contains('.')
            {
                out.insert(recv.to_string());
            }
        }
        if info.kind == StmtKind::Return || info.implicit_return {
            out.extend(info.returned_idents.iter().cloned());
        }
        if info.managed_resource
            && let Some(d) = info.taint.defines.as_deref()
        {
            out.insert(d.to_string());
            facts.managed.insert(d.to_string());
        }
        let stores_away = info.escaping_store
            || info
                .taint
                .defines
                .as_deref()
                .is_some_and(|d| d.contains('.'));
        if stores_away && info.kind == StmtKind::Seq {
            out.extend(info.taint.uses.iter().cloned());
        }
        for i in container_insert_arg_positions(lang, info) {
            out.insert(info.call.arg_uses[i][0].clone());
        }
    }
    facts
}

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
    /// A C function that releases its parameter at this index
    /// (`static void cleanup(struct t *p) { free(p); }`); a call passing an
    /// OPEN handle there releases it.  Plain functions only, never a method.
    ReleaseParam(usize),
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
    /// Optional set of C/C++ struct-value container base names whose
    /// field-acquire (`c.buf = malloc()`) provably does NOT transfer
    /// ownership — the container is a locally-declared value struct that
    /// never escapes the function, so the acquire genuinely leaks and the
    /// `acquire_into_field_transfers_ownership` suppression must be lifted.
    /// Computed once per body by
    /// `nonescaping_local_field_containers` in `run_state_analysis`.
    /// Strict-additive: when `None`, the blanket suppression stands.
    pub nonescaping_field_containers: Option<&'a std::collections::HashSet<String>>,
    /// Java only: names of wrapper objects that this body closes, returns,
    /// manages with try-with-resources, or stores away (see
    /// `closeable_wrapper_names`).  A stream handed to the constructor of
    /// one of these (`new BufferedInputStream(in)`) is owned by the wrapper
    /// from then on.  `None` disables the handoff.
    pub closeable_wrappers: Option<&'a CloseableWrappers>,
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

        // A node that reassigns a Go error companion (or its resource)
        // breaks the pairing: after `_, err = f.Write(b)` an `err != nil`
        // branch says nothing about whether `f` was acquired.  The acquire
        // that re-binds a pair runs after this in `apply_call`.
        if self.lang == Lang::Go {
            self.kill_redefined_err_companions(info, &mut state);
        }

        // C++ smart pointer adopting a raw pointer (`std::unique_ptr<T>
        // p(raw)`): RAII now owns `raw`.  Runs before the assignment
        // transfer so `raw`'s OPEN state is not copied onto `p`.
        if self.lang == Lang::Cpp {
            for u in &info.call.ctor_owned_args {
                if let Some(sym) = self.get_sym(info, u)
                    && state.resource.get(sym).contains(ResourceLifecycle::OPEN)
                {
                    state.resource.set(sym, ResourceLifecycle::MOVED);
                }
            }
        }

        // A name bound to an offset or sub-object address of an OPEN handle
        // stands for that handle when it is released, handed on or stored.
        let rewritten = self.rewrite_aliases(info, &state);
        let info = rewritten.as_ref().unwrap_or(info);
        if let Some(def) = info.taint.defines.as_deref()
            && !state.sub_aliases.is_empty()
            && let Some(def_sym) = self.get_sym(info, def)
        {
            state.sub_aliases.remove(&def_sym);
        }

        match info.kind {
            StmtKind::Call => {
                self.apply_call(node_idx, info, &mut state, &mut events);
            }
            StmtKind::If => {
                self.apply_cond_release(node_idx, info, &mut state, &mut events);
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
    /// `info` with every alias of an OPEN handle replaced by the handle's
    /// name in its uses and call arguments, or `None` when nothing changes.
    /// A store into the alias (`s[-1] = t`) is left alone: it writes through
    /// the pointer, it does not hand the handle on.
    fn rewrite_aliases(&self, info: &NodeInfo, state: &ProductState) -> Option<NodeInfo> {
        if state.sub_aliases.is_empty() {
            return None;
        }
        let mut names: Vec<(&str, &str)> = Vec::new();
        for (alias, root) in &state.sub_aliases {
            if state.resource.get(*root).contains(ResourceLifecycle::OPEN) {
                names.push((self.interner.resolve(*alias), self.interner.resolve(*root)));
            }
        }
        if names.is_empty() {
            return None;
        }
        let swap = |n: &str| names.iter().find(|(a, _)| *a == n).map(|(_, r)| *r);
        let def_base = info.taint.defines.as_deref().map(|d| {
            d.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("")
        });
        let store_through = info.kind == StmtKind::Seq
            && def_base.is_some_and(|b| names.iter().any(|(a, _)| *a == b))
            && info.taint.defines.as_deref() != def_base;
        let touches = |v: &[String]| v.iter().any(|n| swap(n).is_some());
        if store_through
            || !(touches(&info.taint.uses) || info.call.arg_uses.iter().any(|a| touches(a)))
        {
            return None;
        }
        let mut out = info.clone();
        let fix = |v: &mut Vec<String>| {
            for n in v.iter_mut() {
                if let Some(r) = swap(n) {
                    *n = r.to_string();
                }
            }
            v.dedup();
        };
        fix(&mut out.taint.uses);
        for a in out.call.arg_uses.iter_mut() {
            fix(a);
        }
        Some(out)
    }

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
            if !self.proxy_name_matches(&summary.method_name, info, method_suffix) {
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
                ResourceEffect::ReleaseParam(_) => {}
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

    /// Whether a resource method summary named `summary_name` is the method
    /// the call in `info` invokes (`method_lower` is its lowercased name).
    /// Method names are case-sensitive except in PHP: Go `buf.Write` is not
    /// a call to `func write`.
    fn proxy_name_matches(&self, summary_name: &str, info: &NodeInfo, method_lower: &str) -> bool {
        if self.lang == Lang::Php {
            return summary_name.eq_ignore_ascii_case(method_lower);
        }
        info.call
            .callee
            .as_deref()
            .and_then(try_chain_decompose)
            .is_some_and(|(_, method)| method == summary_name)
    }

    /// Whether `callee_lower` operates on a resource handle: a use pattern of
    /// any resource pair, or the global fallback list.
    fn is_use_callee(&self, callee_lower: &str) -> bool {
        self.resource_pairs
            .iter()
            .flat_map(|pair| pair.use_patterns.iter())
            .chain(RESOURCE_USE_PATTERNS.iter())
            .any(|p| use_callee_matches(self.lang, callee_lower, p))
    }

    /// Report a use-after-close for every CLOSED handle this use call
    /// operates on.
    ///
    /// C, C++ and Rust count any mention: reading through a freed pointer
    /// (`strcpy(buf, n->name)` after `free(n)`) is itself the bug.  In the
    /// handle languages a closed object stays alive, so reading its name or
    /// path (`f.name`, `f.Name()`, `tmp.path`) is fine.  There only the
    /// handle the call works on counts: the receiver of the matched method,
    /// a handle passed whole as an argument (`fwrite($fh, ..)`,
    /// `fmt.Fprintf(f, ..)`), or the receiver of a nested use call
    /// (`out.write(f.read())`).
    fn emit_use_after_close(
        &self,
        node_idx: NodeIndex,
        info: &NodeInfo,
        state: &ProductState,
        events: &mut Vec<TransferEvent>,
    ) {
        let any_mention = matches!(self.lang, Lang::C | Lang::Cpp | Lang::Rust);
        let mut operands: smallvec::SmallVec<[&str; 4]> = smallvec::SmallVec::new();
        if !any_mention {
            if let Some(r) = info.call.receiver.as_deref() {
                operands.push(r);
            }
            if let Some((r, _)) = info.call.callee.as_deref().and_then(try_chain_decompose) {
                operands.push(r);
            }
            for arg in &info.call.arg_uses {
                if let [whole] = arg.as_slice() {
                    operands.push(whole);
                }
            }
            for inner in info.arg_callees.iter().flatten() {
                if let Some((r, _)) = try_chain_decompose(inner)
                    && self.is_use_callee(&inner.to_ascii_lowercase())
                {
                    operands.push(r);
                }
            }
        }
        let mut reported: smallvec::SmallVec<[SymbolId; 2]> = smallvec::SmallVec::new();
        for used in &info.taint.uses {
            if !any_mention && !operands.contains(&used.as_str()) {
                continue;
            }
            if let Some(sym) = self.get_sym(info, used)
                && !reported.contains(&sym)
                && state.resource.get(sym) == ResourceLifecycle::CLOSED
            {
                reported.push(sym);
                events.push(TransferEvent {
                    kind: TransferEventKind::UseAfterClose,
                    node: node_idx,
                    var: sym,
                });
            }
        }
    }

    /// Drop Go error-companion pairs whose error or resource symbol this
    /// node reassigns.
    fn kill_redefined_err_companions(&self, info: &NodeInfo, state: &mut ProductState) {
        for name in info
            .taint
            .defines
            .iter()
            .chain(info.taint.extra_defines.iter())
        {
            if let Some(sym) = self.get_sym(info, name) {
                state.err_companions.kill(sym);
            }
        }
    }

    /// Release effect of a call to `callee` whose operands are `uses`: moves
    /// each OPEN operand to CLOSED and reports a second close.  Returns true
    /// when `callee` is a release of some resource pair.  `strict` limits the
    /// match to the callee itself or a method of that name, so a predicate
    /// such as `should_close(f)` is not a close.
    // Each argument is an independent piece of the transfer state; a context struct would only rename them.
    #[allow(clippy::too_many_arguments)]
    fn apply_release(
        &self,
        strict: bool,
        node_idx: NodeIndex,
        info: &NodeInfo,
        callee: &str,
        uses: &[String],
        released: &mut smallvec::SmallVec<[SymbolId; 4]>,
        state: &mut ProductState,
        events: &mut Vec<TransferEvent>,
    ) -> bool {
        // `released` tracks the variables already released, to avoid double-
        // matching across multiple resource pair definitions.
        let mut direct_release = false;
        for pair in self.resource_pairs {
            let is_release = pair.release.iter().any(|r| {
                if strict {
                    rules::callee_matches_at_boundary(callee, &r.to_ascii_lowercase())
                } else {
                    callee_matches(callee, r)
                }
            });
            if is_release {
                direct_release = true;
                // Go `defer f.Close()`: skip the CLOSED transition so the
                // variable stays OPEN mid-function.  Leak suppression is
                // handled separately in extract_findings().
                if info.in_defer {
                    continue;
                }
                for used in uses {
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
        direct_release
    }

    /// A call to a function of this file that releases one of its
    /// parameters: the OPEN handle passed at that position is released.
    fn apply_release_wrappers(&self, info: &NodeInfo, state: &mut ProductState) {
        if self.lang != Lang::C {
            return;
        }
        let Some(callee) = info.call.callee.as_deref() else {
            return;
        };
        for summary in self.resource_method_summaries {
            let ResourceEffect::ReleaseParam(k) = summary.effect else {
                continue;
            };
            if summary.method_name != callee {
                continue;
            }
            // The caller's argument must be exactly the handle (not `&h`),
            // and the call must not rebind that same variable
            // (`fd = wrapper(fd)`): the result replaces the handle.
            if k < 64
                && info.call.arg_bare_names & (1u64 << k) != 0
                && let Some([arg]) = info.call.arg_uses.get(k).map(Vec::as_slice)
                && info.taint.defines.as_deref() != Some(arg.as_str())
                && let Some(sym) = self.get_sym(info, arg)
                && state.resource.get(sym).contains(ResourceLifecycle::OPEN)
            {
                state.resource.set(sym, ResourceLifecycle::CLOSED);
            }
        }
    }

    /// A release call in an `if` condition (`if (fclose(f)) die(..)`) runs
    /// before either branch, so its effect applies on both outgoing edges
    /// even though the header is not a `StmtKind::Call`.  Only releases are
    /// applied: a condition call never acquires or hands off here.
    fn apply_cond_release(
        &self,
        node_idx: NodeIndex,
        info: &NodeInfo,
        state: &mut ProductState,
        events: &mut Vec<TransferEvent>,
    ) {
        let Some(cc) = info.cond_call.as_deref() else {
            return;
        };
        let callee = cc.callee.to_ascii_lowercase();
        let mut uses: Vec<String> = cc.arg_uses.iter().flatten().cloned().collect();
        if let Some((receiver, _)) = cc.callee.rsplit_once('.')
            && !receiver.contains('(')
        {
            uses.push(receiver.to_string());
        }
        let mut released = smallvec::SmallVec::new();
        self.apply_release(
            true,
            node_idx,
            info,
            &callee,
            &uses,
            &mut released,
            state,
            events,
        );
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
        // SAFE-FOR-FIELD-LHS: skip member-expression LHS acquires.  A
        // `b.cpuprof = os.Create(...)` (Go) / `c->connect_timeout =
        // hi_malloc(...)` (C) pattern transfers ownership to the containing
        // struct; the local function body cannot observe the release (which
        // lives in a paired Stop()/dispose()/free_*() method, or in the
        // caller when the struct is a parameter), so tracking the field as a
        // local resource is a guaranteed FP at function exit.  Mirrors the
        // ownership-transfer suppression in
        // src/cfg_analysis::resources::is_ownership_transferred (cfg twin).
        // Production triggers: prometheus cmd/promtool/tsdb.go::startProfiling
        // (b.cpuprof, b.memprof, ...); redis/hiredis net.c
        // redisContextUpdateConnectTimeout (c->connect_timeout), lua strbuf.c
        // (s->buf).  Excludes JS/TS (see
        // `acquire_into_field_transfers_ownership`) because the class-field
        // acquire `this.fd = fs.openSync(...)` IS the expected leak pattern
        // the TS state fixtures rely on.
        let mut direct_acquire = false;
        // Field-LHS ownership-transfer suppression, LIFTED for a provably
        // non-escaping local value struct (`struct Ctx c; c.buf = malloc()`
        // where `c` dies at function exit and is never freed — a real leak).
        // See `nonescaping_local_field_containers`.
        let define_is_field_lhs = info.taint.defines.as_deref().is_some_and(|d| {
            acquire_into_field_transfers_ownership(self.lang, d)
                && !self
                    .nonescaping_field_containers
                    .is_some_and(|set| field_container_is_nonescaping(set, d))
        });
        // Acquires stored straight into a global, an unqualified field, a
        // pointer target (`*out = malloc(n)`) or a container element are
        // owned by whatever holds that storage, exactly like the field case.
        let define_is_field_lhs = define_is_field_lhs || info.escaping_store;
        let resource_pairs_iter: &[ResourcePair] = if define_is_field_lhs {
            &[]
        } else {
            self.resource_pairs
        };
        for pair in resource_pairs_iter {
            // Go `sync.Mutex` / `RWMutex` `Lock` returns nothing, and this
            // pass only tracks an acquire through the value it binds.  So a
            // bound `.Lock()` result (`cache := store.lock()`,
            // `ok := l.Lock(ctx)`) is a user method that shares the name,
            // not a held lock.  Go locks are checked by the cfg twin.
            if self.lang == Lang::Go && pair.resource_name == "mutex" {
                continue;
            }
            let is_acquire = pair
                .acquire
                .iter()
                .any(|a| acquire_callee_matches(self.lang, &callee, a));
            let is_excluded = pair
                .exclude_acquire
                .iter()
                .any(|e| acquire_callee_matches(self.lang, &callee, e));

            // A callee promoted out of another call's arguments binds nothing
            // here (the definition holds the outer call's result), and a
            // hoisted member read is no call of this node at all.
            if is_acquire
                && !is_excluded
                && info.call.callee_nesting == CalleeNesting::Own
                && let Some(ref def) = info.taint.defines
                && let Some(sym) = self.get_sym(info, def)
            {
                state.resource.set(sym, ResourceLifecycle::OPEN);
                state.acquire_spans.insert(sym, info.ast.span);
                direct_acquire = true;
                // Go `f, err := os.Open(p)`: pair the handle with the error
                // result so `if err != nil { return err }` can prune the
                // failure branch (see `apply_if`).
                if self.lang == Lang::Go {
                    for extra in &info.taint.extra_defines {
                        if let Some(err_sym) = self.get_sym(info, extra)
                            && err_sym != sym
                        {
                            state.err_companions.bind(err_sym, sym);
                        }
                    }
                }
            }
        }

        // ── Resource release ─────────────────────────────────────────────
        let mut released: smallvec::SmallVec<[SymbolId; 4]> = smallvec::SmallVec::new();
        let direct_release = self.apply_release(
            false,
            node_idx,
            info,
            &callee,
            &info.taint.uses,
            &mut released,
            state,
            events,
        );
        // ── Call to a same-file function that frees its parameter ────────
        if !direct_acquire && !direct_release && !info.in_defer {
            self.apply_release_wrappers(info, state);
        }
        // ── Value stored through a call result ───────────────────────────
        // `get(l, k)->util = item;` / `*slot_at(c) = name;`: the target is
        // storage the call hands out, so the stored handle now belongs there.
        // The call's own arguments are not stored; only the other operands.
        if info.escaping_store && !direct_acquire && !direct_release {
            for used in &info.taint.uses {
                if info.call.arg_uses.iter().flatten().any(|a| a == used) {
                    continue;
                }
                if let Some(sym) = self.get_sym(info, used)
                    && state.resource.get(sym).contains(ResourceLifecycle::OPEN)
                {
                    state.resource.set(sym, ResourceLifecycle::MOVED);
                }
            }
        }

        // ── Ownership handed to a container or wrapper ───────────────────
        if !direct_acquire && !direct_release {
            for i in container_insert_arg_positions(self.lang, info) {
                let u = &info.call.arg_uses[i][0];
                if info.call.receiver.as_deref() == Some(u.as_str()) {
                    continue;
                }
                if let Some(sym) = self.get_sym(info, u)
                    && state.resource.get(sym).contains(ResourceLifecycle::OPEN)
                {
                    state.resource.set(sym, ResourceLifecycle::MOVED);
                }
            }
        }
        // Java decorator streams: `BufferedInputStream b = new
        // BufferedInputStream(in)` makes `b` the owner of `in` (closing `b`
        // closes `in`).  Only when `b` itself is closed, returned, managed
        // or stored away; `new InputSource(in)` followed by `in.close()`
        // must keep `in` as the tracked handle.
        if self.lang == Lang::Java
            && info.call.is_constructor
            && !define_is_field_lhs
            && let Some(w) = info.taint.defines.as_deref()
            && let Some(wrappers) = self.closeable_wrappers
            && wrappers.names.contains(w)
            && let Some(w_sym) = self.get_sym(info, w)
        {
            for u in &info.call.ctor_owned_args {
                if u == w || wrappers.managed.contains(u) {
                    continue;
                }
                let Some(u_sym) = self.get_sym(info, u) else {
                    continue;
                };
                let u_lc = state.resource.get(u_sym);
                if !u_lc.contains(ResourceLifecycle::OPEN) {
                    continue;
                }
                let w_lc = if direct_acquire {
                    state.resource.get(w_sym)
                } else {
                    u_lc
                };
                state.resource.set(w_sym, w_lc);
                state.resource.set(u_sym, ResourceLifecycle::MOVED);
            }
        }

        // INNER-CALL-RELEASE-IN-ARG: walk info.arg_callees so a release
        // method that lives in argument position is still observed.
        // Production triggers: `require.NoError(t, f.Close())` (Go
        // testify), `errs = append(errs, f.Close())`, JUnit
        // `assertEquals(0, in.read())`.  Conservative: bare-receiver
        // inner calls only (recv has no dot — chained-receiver
        // releases are owned by chain_proxies which doesn't observe
        // inner-call positions today); marks CLOSED only (no
        // DoubleClose since attribution is approximate); respects
        // in_defer for symmetry with the direct-release branch above.
        if !info.in_defer && !info.arg_callees.is_empty() {
            for arg_callee in &info.arg_callees {
                let Some(arg_callee_text) = arg_callee.as_deref() else {
                    continue;
                };
                let Some((recv_text, _method)) = try_chain_decompose(arg_callee_text) else {
                    continue;
                };
                if recv_text.contains('.') {
                    continue;
                }
                let arg_callee_lower = arg_callee_text.to_ascii_lowercase();
                let matches_release = self.resource_pairs.iter().any(|p| {
                    p.release
                        .iter()
                        .any(|r| callee_matches(&arg_callee_lower, r))
                });
                if !matches_release {
                    continue;
                }
                let Some(sym) = self.get_sym(info, recv_text) else {
                    continue;
                };
                if released.contains(&sym) {
                    continue;
                }
                let current = state.resource.get(sym);
                if current.contains(ResourceLifecycle::OPEN) {
                    state.resource.set(sym, ResourceLifecycle::CLOSED);
                    released.push(sym);
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
                    if !self.proxy_name_matches(&summary.method_name, info, method_suffix) {
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
                        ResourceEffect::ReleaseParam(_) => {}
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
                    if !self.proxy_name_matches(&summary.method_name, info, method_suffix) {
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
                        ResourceEffect::ReleaseParam(_) => {}
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

        // ── Resource use (pair-specific patterns, then the global fallback)
        if self.is_use_callee(&callee) {
            self.emit_use_after_close(node_idx, info, state, events);
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

        // Resource null-check: on the branch where a tracked handle is null
        // (or its failure sentinel), the acquire produced nothing, so no
        // close is owed on that path.  Covers the NULL-safe close idiom and
        // the check-and-return idiom in every spelling the CFG builder
        // recognises (`if (f)`, `if (!f)`, `f == NULL`, `NULL != f`,
        // `f is None`, `$fh === false`, `fd < 0`):
        //
        //     FILE *f = fopen(path, "r");
        //     if (f == NULL) return -1;
        //     ...
        //     fclose(f);
        //
        // Without this the null edge keeps OPEN, joins with the CLOSED of
        // the success path at function exit, and reports a may-leak on
        // correct code.
        if let Some(nc) = &info.null_check {
            if edge == Some(nc.null_edge())
                && let Some(sym) = self.get_sym(info, &nc.var)
            {
                clear_open(state, sym);
            }
            // Go error companion: on the `err != nil` branch the paired
            // acquire failed and its handle is the zero value.
            if self.lang == Lang::Go
                && edge == Some(nc.non_null_edge())
                && let Some(err_sym) = self.get_sym(info, &nc.var)
            {
                let paired: smallvec::SmallVec<[SymbolId; 2]> =
                    state.err_companions.resources_of(err_sym).collect();
                for res in paired {
                    clear_open(state, res);
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
            let is_auth_cond = condition_is_auth_test(cond_inner, self.lang);
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
            // `close(fd); fd = -1;` / `free(p); p = NULL;`: once a released
            // handle's variable is overwritten with a constant it no longer
            // names that handle, so a later guarded release
            // (`if (fd >= 0) close(fd);`) is not a second close.  An OPEN
            // handle keeps its state: overwriting it is a leak, not a reset.
            let lc = state.resource.get(def_sym);
            if info.taint.uses.is_empty() && !lc.is_empty() && !lc.contains(ResourceLifecycle::OPEN)
            {
                state.resource.set(def_sym, ResourceLifecycle::empty());
                return;
            }
            // SAFE-FOR-FIELD-LHS: when the LHS is a member expression
            // (struct field / object property), do NOT track the field as
            // a separate resource — the parent struct/object owns the
            // field's lifecycle and the local function body cannot
            // observe whether/when the parent's destructor (or paired
            // Stop()/dispose() method on the parent) releases the
            // underlying storage.  Still mark the RHS as MOVED so the
            // local-leak analysis treats the assignment as ownership
            // transfer to the parent, not as a continuing local handle.
            //
            // Two real-repo shapes this closes (curl, openssl, postgres):
            //
            //   (i) Sub-buffer alias inside a returned struct:
            //       e = curlx_calloc(...);
            //       e->name = (char *)e + sizeof(*e);  // sub-buffer alias
            //       return e;
            //   Without this gate, e's OPEN transferred to e->name, e went
            //   MOVED, and e->name surfaced as "never closed".
            //
            //   (ii) Local-into-field ownership transfer:
            //       ptr = malloc(...);
            //       mem->buf = ptr;        // ownership now lives in *mem
            //   Without this gate, ptr was MOVED to mem->buf, but mem->buf
            //   then leaked at exit because *mem's lifecycle is owned by
            //   the caller.  With this gate, ptr is MOVED (transfer
            //   acknowledged) and mem->buf is not separately tracked.
            //
            // Multi-language: applies to all languages.  This is distinct
            // from the `apply_call` field-LHS gate (Go-only because the
            // documented TS/JS class-field acquire
            // `this.fd = fs.openSync(...)` IS the expected leak pattern
            // in tests/fixtures/.../typescript/state/resource_class.ts —
            // that path remains untouched here because RHS-is-a-call
            // routes through `apply_call`, not `apply_assignment`).
            // A read-modify-write (`p += n`, `p++`) lists its own target as
            // a use: the handle stays where it is, it does not move to itself.
            // The same holds for an `escaping_store`: `*out = buf`,
            // `g_cache = buf`, `this.in = s` written as `in = s` in Java,
            // `handles[i] = f`.
            let not_rmw_self = |u: &&String| !(info.rmw_assign && *u == def);
            if def.contains('.') || def.contains("->") || info.escaping_store {
                for used in info.taint.uses.iter().filter(not_rmw_self) {
                    if let Some(use_sym) = self.get_sym(info, used) {
                        let lc = state.resource.get(use_sym);
                        if lc.contains(ResourceLifecycle::OPEN) {
                            state.resource.set(use_sym, ResourceLifecycle::MOVED);
                            return;
                        }
                    }
                }
                return;
            }
            // The address of a sub-object (`c = &ac->c`), an aggregate
            // initializer or arithmetic on a handle is not the handle: it
            // stays with its own name.  A projection (`cur = cur->next`) is
            // another object; rebinding the walker to it drops the name's
            // claim on the handle it held.
            match info.rhs_shape {
                RhsShape::SubObject | RhsShape::CastView => {
                    // `s = sh + n`, `b = &it->base`: `s` points into the
                    // handle's storage.  The handle keeps its state, `s`
                    // is remembered as a way to release or hand it on.
                    for used in info.taint.uses.iter().filter(not_rmw_self) {
                        if let Some(use_sym) = self.get_sym(info, used)
                            && use_sym != def_sym
                            && state
                                .resource
                                .get(use_sym)
                                .contains(ResourceLifecycle::OPEN)
                        {
                            state.sub_aliases.insert(def_sym, use_sym);
                            break;
                        }
                    }
                    return;
                }
                RhsShape::Aggregate => {
                    // The handle is stored in the aggregate; whoever holds
                    // the aggregate owns it now.
                    for used in info.taint.uses.iter().filter(not_rmw_self) {
                        if let Some(use_sym) = self.get_sym(info, used)
                            && state
                                .resource
                                .get(use_sym)
                                .contains(ResourceLifecycle::OPEN)
                        {
                            state.resource.set(use_sym, ResourceLifecycle::MOVED);
                        }
                    }
                    return;
                }
                RhsShape::Projection => {
                    if info.taint.uses.iter().any(|u| u == def)
                        && state
                            .resource
                            .get(def_sym)
                            .contains(ResourceLifecycle::OPEN)
                    {
                        state.resource.set(def_sym, ResourceLifecycle::MOVED);
                    }
                    return;
                }
                RhsShape::Whole => {}
            }
            // Reading a field of a handle (`desc = cursor.description`,
            // `n = node->next`) yields a different value; the handle itself
            // stays put.  Only a plain alias (`g = f`) moves it.
            if info.member_field.is_some() {
                return;
            }
            // If the RHS is a tracked resource, transfer its state
            for used in info.taint.uses.iter().filter(not_rmw_self) {
                if let Some(use_sym) = self.get_sym(info, used) {
                    let lc = state.resource.get(use_sym);
                    if lc.contains(ResourceLifecycle::OPEN) {
                        state.resource.set(def_sym, lc);
                        state.resource.set(use_sym, ResourceLifecycle::MOVED);
                        if let Some(span) = state.acquire_spans.get(&use_sym).copied() {
                            state.acquire_spans.insert(def_sym, span);
                        }
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

/// Whether `callee_lower` is an acquire for `pattern`.
///
/// Outside C/C++ an acquire must match at an identifier boundary, the same
/// rule the cfg twin uses: `disconnect` / `reconnect` are not `connect`,
/// `is_open` / `_ensure_open` / `subprocess.Popen` / `mock_open` are not
/// `open`, `websocket` is not `socket`, `decode_cursor` is not `cursor`.
/// A raw suffix match turned every one of those results into an OPEN
/// handle that was "never closed".
///
/// C/C++ keep the suffix match on purpose: prefixed allocators and
/// `*_open` / `*_close` families are the house style there (`xmalloc`,
/// `zmalloc`, `curlx_calloc`, `pg_malloc`, `table_open`, `iconv_open`,
/// `dlopen`), and the matching suffix release pairs them up.  Release
/// matching stays lenient everywhere: it only ever clears OPEN, so it cannot
/// produce a leak.
pub(crate) fn acquire_callee_matches(lang: Lang, callee_lower: &str, pattern: &str) -> bool {
    match lang {
        Lang::C | Lang::Cpp => callee_matches(callee_lower, pattern),
        _ => rules::callee_matches_at_boundary(callee_lower, &pattern.to_ascii_lowercase()),
    }
}

/// Whether `callee_lower` is a use of a resource handle for `pattern`.
///
/// Outside C/C++ a bare pattern must start at a word boundary: `read` does
/// not match `spawn_thread` or `threading.Thread`, and `write` does not
/// match `overwrite`.  An underscore still counts as a boundary, so
/// snake_case wrappers (`safe_write(f, ..)`) keep matching.  C/C++ keep the
/// plain suffix match, like their acquires.
fn use_callee_matches(lang: Lang, callee_lower: &str, pattern: &str) -> bool {
    if matches!(lang, Lang::C | Lang::Cpp) || pattern.starts_with('.') {
        return callee_matches(callee_lower, pattern);
    }
    let pattern_lower = pattern.to_ascii_lowercase();
    let Some(prefix) = callee_lower.strip_suffix(pattern_lower.as_str()) else {
        return false;
    };
    prefix
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_ascii_alphanumeric())
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

/// Remove OPEN from a symbol's lifecycle (the path on which the handle was
/// never produced).
fn clear_open(state: &mut ProductState, sym: SymbolId) {
    let lc = state.resource.get(sym);
    if lc.contains(ResourceLifecycle::OPEN) {
        state
            .resource
            .set(sym, lc.difference(ResourceLifecycle::OPEN));
    }
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

/// Whether `cond` (already lowercased) names an authentication or
/// authorization check of `lang`: one of the call matchers, or a predicate that
/// is only meaningful as a condition.
pub(crate) fn condition_is_auth_test(cond: &str, lang: Lang) -> bool {
    rules::auth_rules(lang)
        .iter()
        .flat_map(|rule| rule.matchers.iter())
        .chain(rules::auth_condition_matchers(lang))
        .any(|m| condition_contains_auth_token(cond, m))
}

/// Check if condition text contains an auth/admin matcher at a word boundary.
///
/// Dispatches based on matcher content:
/// - **Identifier-only** (`is_authenticated`, `require_auth`): tokenise condition
///   text on non-identifier characters and require an exact token match.
/// - **Contains punctuation** (`middleware.auth`): find the matcher as a substring
///   and verify word boundaries (non-ident char or string edge) on both sides.
pub(crate) fn condition_contains_auth_token(cond: &str, matcher: &str) -> bool {
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
    fn acquire_into_field_transfers_ownership_c_cpp_arrow_and_dot() {
        // C/C++: both pointer-member (`->`) and value-member (`.`) LHS transfer
        // ownership to the containing struct/object.
        assert!(acquire_into_field_transfers_ownership(
            Lang::C,
            "c->connect_timeout"
        ));
        assert!(acquire_into_field_transfers_ownership(Lang::C, "s->buf"));
        assert!(acquire_into_field_transfers_ownership(
            Lang::C,
            "cfg.handle"
        ));
        assert!(acquire_into_field_transfers_ownership(
            Lang::Cpp,
            "this->fd"
        ));
        // Plain locals are still tracked (real leaks).
        assert!(!acquire_into_field_transfers_ownership(Lang::C, "p"));
        assert!(!acquire_into_field_transfers_ownership(Lang::C, "orphan"));
    }

    #[test]
    fn acquire_into_field_transfers_ownership_go_dot_only() {
        // Go uses `.` field access; it has no `->` operator.
        assert!(acquire_into_field_transfers_ownership(
            Lang::Go,
            "b.cpuprof"
        ));
        assert!(!acquire_into_field_transfers_ownership(Lang::Go, "profile"));
    }

    #[test]
    fn single_ident_dot_container_shapes() {
        assert_eq!(single_ident_dot_container("c.buf"), Some("c"));
        assert_eq!(single_ident_dot_container("cfg.handle"), Some("cfg"));
        // Pointer member → container escapes; subscript / sub-object / no-dot
        // are all out of scope for the local-value-struct recovery.
        assert_eq!(single_ident_dot_container("c->buf"), None);
        assert_eq!(single_ident_dot_container("arr[i].buf"), None);
        assert_eq!(single_ident_dot_container("c.inner.buf"), None);
        assert_eq!(single_ident_dot_container("buf"), None);
        assert_eq!(single_ident_dot_container(".buf"), None);
        assert_eq!(single_ident_dot_container("c."), None);
    }

    fn seq_decl(name: &str) -> NodeInfo {
        NodeInfo {
            kind: StmtKind::Seq,
            taint: TaintMeta {
                uses: vec![name.to_string()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn field_malloc(def: &str) -> NodeInfo {
        NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                defines: Some(def.to_string()),
                uses: vec!["malloc".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("malloc".into()),
                arg_uses: vec![vec![]],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn nonescaping_local_field_containers_escape_analysis() {
        use crate::cfg::Cfg;
        use petgraph::graph::Graph;
        let mut cfg: Cfg = Graph::new();
        // `struct Ctx c; c.buf = malloc();`  → non-escaping local (fires)
        cfg.add_node(seq_decl("c"));
        cfg.add_node(field_malloc("c.buf"));
        // `struct Ctx h = {0}; h.buf = malloc();`  → initializer-decl local
        cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            taint: TaintMeta {
                defines: Some("h".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        cfg.add_node(field_malloc("h.buf"));
        // `struct Ctx e; e.buf = malloc(); init(&e);` → address-taken escape
        cfg.add_node(seq_decl("e"));
        cfg.add_node(field_malloc("e.buf"));
        cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                uses: vec!["init".into(), "e".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("init".into()),
                arg_uses: vec![vec!["e".into()]],
                ..Default::default()
            },
            ..Default::default()
        });

        let set = nonescaping_local_field_containers(&cfg, Lang::C);
        assert!(
            set.contains("c"),
            "non-escaping `c` must be present: {set:?}"
        );
        assert!(
            set.contains("h"),
            "initializer-decl local `h` must be present: {set:?}"
        );
        assert!(
            !set.contains("e"),
            "address-taken `e` must be absent: {set:?}"
        );

        assert!(field_container_is_nonescaping(&set, "c.buf"));
        assert!(field_container_is_nonescaping(&set, "h.buf"));
        assert!(!field_container_is_nonescaping(&set, "e.buf"));
        // Arrow form is never a candidate, even if the base were in the set.
        assert!(!field_container_is_nonescaping(&set, "c->buf"));

        // Non-C/C++ languages are unaffected (Go/JS keep prior behaviour).
        assert!(nonescaping_local_field_containers(&cfg, Lang::Go).is_empty());
        assert!(nonescaping_local_field_containers(&cfg, Lang::JavaScript).is_empty());
    }

    #[test]
    fn nonescaping_requires_local_decl_excludes_param_and_global() {
        use crate::cfg::Cfg;
        use petgraph::graph::Graph;
        // `g.buf = malloc()` with NO body declaration for `g` — `g` is a
        // parameter or a global, whose field allocation is not a
        // function-local leak.  Must NOT fire.
        let mut cfg: Cfg = Graph::new();
        cfg.add_node(field_malloc("g.buf"));
        let set = nonescaping_local_field_containers(&cfg, Lang::C);
        assert!(
            !set.contains("g"),
            "container without a body decl must be absent: {set:?}"
        );
    }

    #[test]
    fn nonescaping_field_read_passed_to_call_is_escape() {
        use crate::cfg::Cfg;
        use petgraph::graph::Graph;
        // `struct Ctx c; c.buf = malloc(); log_it(c.tag);` — passing a field
        // read surfaces bare `c`, conservatively treated as an escape.
        let mut cfg: Cfg = Graph::new();
        cfg.add_node(seq_decl("c"));
        cfg.add_node(field_malloc("c.buf"));
        cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                uses: vec!["c.tag".into(), "log_it".into(), "c".into(), "tag".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("log_it".into()),
                arg_uses: vec![vec!["c.tag".into(), "c".into(), "tag".into()]],
                ..Default::default()
            },
            ..Default::default()
        });
        let set = nonescaping_local_field_containers(&cfg, Lang::C);
        assert!(
            !set.contains("c"),
            "field read passed to a call must be treated as escape: {set:?}"
        );
    }

    #[test]
    fn acquire_into_field_transfers_ownership_js_ts_never() {
        // JS/TS: the class-field acquire `this.fd = fs.openSync(...)` IS the
        // expected leak pattern the TS state fixtures rely on — never suppress.
        assert!(!acquire_into_field_transfers_ownership(
            Lang::JavaScript,
            "this.fd"
        ));
        assert!(!acquire_into_field_transfers_ownership(
            Lang::TypeScript,
            "this.socket"
        ));
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

    fn call_node(callee: &str, defines: Option<&str>, arg_uses: Vec<Vec<&str>>) -> NodeInfo {
        NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                defines: defines.map(String::from),
                uses: arg_uses.iter().flatten().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some(callee.into()),
                arg_uses: arg_uses
                    .into_iter()
                    .map(|a| a.into_iter().map(String::from).collect())
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn container_insert_positions_by_language() {
        let pos = |lang, info: &NodeInfo| container_insert_arg_positions(lang, info).to_vec();
        assert_eq!(
            pos(Lang::Cpp, &call_node("v.push_back", None, vec![vec!["f"]])),
            vec![0]
        );
        assert_eq!(
            pos(
                Lang::Cpp,
                &call_node("v.push_back", None, vec![vec!["f->next", "f"]])
            ),
            Vec::<usize>::new(),
            "an expression argument moves nothing"
        );
        assert_eq!(
            pos(
                Lang::Java,
                &call_node("m.put", None, vec![vec!["k"], vec!["s"]])
            ),
            vec![0, 1]
        );
        assert_eq!(
            pos(
                Lang::JavaScript,
                &call_node("cache.set", None, vec![vec!["fd"]])
            ),
            Vec::<usize>::new(),
            "single-argument `set` is a setter, not a map insert"
        );
        assert_eq!(
            pos(
                Lang::Go,
                &call_node("append", Some("fs"), vec![vec!["fs"], vec!["f"]])
            ),
            vec![1]
        );
        assert_eq!(
            pos(
                Lang::Php,
                &call_node("array_push", None, vec![vec!["a"], vec!["f"]])
            ),
            vec![1]
        );
        assert_eq!(
            pos(Lang::Cpp, &call_node("p.reset", None, vec![vec!["raw"]])),
            vec![0]
        );
        assert_eq!(
            pos(Lang::Python, &call_node("reset", None, vec![vec!["raw"]])),
            Vec::<usize>::new()
        );
        assert_eq!(
            pos(Lang::Python, &call_node("send", None, vec![vec!["f"]])),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn container_insert_moves_open_handle() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");
        interner.intern("v");
        let transfer = DefaultTransfer {
            lang: Lang::Cpp,
            resource_pairs: rules::resource_pairs(Lang::Cpp),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };
        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);
        let (out, _) = transfer.apply(
            NodeIndex::new(1),
            &call_node("v.push_back", None, vec![vec!["f"]]),
            None,
            state,
        );
        assert_eq!(out.resource.get(sym_f), ResourceLifecycle::MOVED);
    }

    fn java_wrapper_node() -> NodeInfo {
        // BufferedInputStream b = new BufferedInputStream(in);
        let mut n = call_node("BufferedInputStream", Some("b"), vec![vec!["in"]]);
        n.call.is_constructor = true;
        n.call.ctor_owned_args = vec!["in".into()];
        n
    }

    #[test]
    fn java_wrapper_takes_ownership_only_when_closeable() {
        let mut interner = SymbolInterner::new();
        let sym_in = interner.intern("in");
        let sym_b = interner.intern("b");
        let closeable = CloseableWrappers {
            names: ["b".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let empty = CloseableWrappers::default();
        let gated = DefaultTransfer {
            lang: Lang::Java,
            resource_pairs: rules::resource_pairs(Lang::Java),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: Some(&closeable),
        };
        let ungated = DefaultTransfer {
            closeable_wrappers: Some(&empty),
            ..gated
        };
        let mut state = ProductState::initial();
        state.resource.set(sym_in, ResourceLifecycle::OPEN);

        let (handed, _) = gated.apply(NodeIndex::new(1), &java_wrapper_node(), None, state.clone());
        assert_eq!(handed.resource.get(sym_in), ResourceLifecycle::MOVED);
        assert_eq!(handed.resource.get(sym_b), ResourceLifecycle::OPEN);

        // `new InputSource(in)` that is never closed: `in` stays the handle.
        let (kept, _) = ungated.apply(NodeIndex::new(1), &java_wrapper_node(), None, state);
        assert_eq!(kept.resource.get(sym_in), ResourceLifecycle::OPEN);
        assert_eq!(kept.resource.get(sym_b), ResourceLifecycle::empty());
    }

    #[test]
    fn acquire_matcher_requires_identifier_boundary_outside_c() {
        let py = |c: &str, p: &str| acquire_callee_matches(Lang::Python, c, p);
        assert!(!py("client.disconnect", "connect"));
        assert!(!py("client.reconnect", "connect"));
        assert!(!py("door.is_open", "open"));
        assert!(!py("store._ensure_open", "open"));
        assert!(!py("subprocess.popen", "open"));
        assert!(!py("mock_open", "open"));
        assert!(!py("factory.websocket", "socket"));
        assert!(!py("decode_cursor", "cursor"));
        assert!(py("open", "open"));
        assert!(py("io.open", "open"));
        assert!(py("psycopg2.connect", "connect"));
        assert!(py("conn.cursor", "cursor"));
        assert!(py("socket.socket", "socket.socket"));
        assert!(py("os.fdopen", "fdopen"));

        let java = |c: &str, p: &str| acquire_callee_matches(Lang::Java, c, p);
        assert!(!java("h.closesocket", "Socket"));
        assert!(java("sf.createsocket", "createSocket"));
        assert!(java("conn.preparestatement", "prepareStatement"));

        let rb = |c: &str, p: &str| acquire_callee_matches(Lang::Ruby, c, p);
        assert!(!rb("file.reopen", "open"));
        assert!(rb("io.popen", "IO.popen"));

        assert!(!acquire_callee_matches(Lang::Rust, "dealloc", "alloc"));
    }

    #[test]
    fn acquire_matcher_stays_lenient_for_c_family() {
        for (callee, pattern) in [
            ("xmalloc", "malloc"),
            ("hi_malloc", "malloc"),
            ("curlx_calloc", "calloc"),
            ("table_open", "open"),
        ] {
            assert!(acquire_callee_matches(Lang::C, callee, pattern), "{callee}");
            assert!(
                acquire_callee_matches(Lang::Cpp, callee, pattern),
                "{callee}"
            );
        }
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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

    /// Count use-after-close events `info` raises with `name` CLOSED.
    fn uac_events(lang: Lang, name: &str, info: &NodeInfo) -> usize {
        let mut interner = SymbolInterner::new();
        let sym = interner.intern(name);
        let transfer = DefaultTransfer {
            lang,
            resource_pairs: rules::resource_pairs(lang),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };
        let mut state = ProductState::initial();
        state.resource.set(sym, ResourceLifecycle::CLOSED);
        let (_state, events) = transfer.apply(NodeIndex::new(1), info, None, state);
        events
            .iter()
            .filter(|e| e.kind == TransferEventKind::UseAfterClose)
            .count()
    }

    #[test]
    fn use_after_close_needs_the_handle_itself_outside_raw_memory_langs() {
        // `sys.stdout.write("%s" % f.name)`: `f` is only reached through an
        // attribute of an argument.
        let attr = call_node("sys.stdout.write", None, vec![vec!["f.name", "f", "name"]]);
        assert_eq!(uac_events(Lang::Python, "f", &attr), 0);
        // `fmt.Fprintf(os.Stderr, "%s", f.Name())`.
        let go_attr = call_node(
            "fmt.Fprintf",
            None,
            vec![
                vec!["os.Stderr", "os", "Stderr"],
                vec![],
                vec!["f.Name", "f"],
            ],
        );
        assert_eq!(uac_events(Lang::Go, "f", &go_attr), 0);

        // Receiver of the matched method: `f.write("x")`.
        let mut recv = call_node("f.write", None, vec![vec![]]);
        recv.taint.uses.push("f".into());
        assert_eq!(uac_events(Lang::Python, "f", &recv), 1);
        // The handle passed whole: `fmt.Fprintf(f, "x")`.
        let whole = call_node("fmt.Fprintf", None, vec![vec!["f"], vec![]]);
        assert_eq!(uac_events(Lang::Go, "f", &whole), 1);
        // A nested use call on the handle: `sys.stdout.write(f.read())`.
        let mut nested = call_node("sys.stdout.write", None, vec![vec!["f.read", "f"]]);
        nested.arg_callees = vec![Some("f.read".into())];
        assert_eq!(uac_events(Lang::Python, "f", &nested), 1);
    }

    #[test]
    fn use_after_close_counts_any_mention_in_c() {
        // `strcpy(buf, n->name)` after `free(n)` reads freed memory.
        let info = call_node(
            "strcpy",
            None,
            vec![vec!["buf"], vec!["n->name", "n", "name"]],
        );
        assert_eq!(uac_events(Lang::C, "n", &info), 1);
    }

    #[test]
    fn use_patterns_match_at_word_boundary_outside_c() {
        assert!(use_callee_matches(Lang::Python, "os.read", "read"));
        assert!(use_callee_matches(Lang::Python, "read", "read"));
        assert!(use_callee_matches(Lang::Python, "safe_write", "write"));
        assert!(use_callee_matches(
            Lang::JavaScript,
            "fs.readsync",
            "readSync"
        ));
        assert!(use_callee_matches(Lang::Go, "f.write", ".write"));
        assert!(!use_callee_matches(
            Lang::Python,
            "pool.spawn_thread",
            "read"
        ));
        assert!(!use_callee_matches(
            Lang::Python,
            "threading.thread",
            "read"
        ));
        assert!(!use_callee_matches(Lang::Python, "overwrite", "write"));
        // C keeps the suffix match (`my_fread`, `xfread`).
        assert!(use_callee_matches(Lang::C, "xfread", "fread"));
    }

    #[test]
    fn is_guard_like_check() {
        assert!(is_guard_like("validate_input"));
        assert!(is_guard_like("sanitize_html"));
        assert!(is_guard_like("check_permission"));
        assert!(!is_guard_like("open_file"));
    }

    /// SAFE-FOR-FIELD-LHS gate: when an assignment writes a tracked
    /// resource into a struct field (`def` contains `.` or `->`), the
    /// RHS local must be marked MOVED (ownership transferred to the
    /// parent struct) and the field must NOT be tracked as a separate
    /// OPEN resource.  Pins the curl/dynhds.c::entry_new shape.
    #[test]
    fn field_lhs_assignment_moves_rhs_and_does_not_track_field() {
        let mut interner = SymbolInterner::new();
        let sym_e = interner.intern("e");
        let sym_field = interner.intern("e->name");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_e, ResourceLifecycle::OPEN);

        // `e->name = e` (sub-buffer alias): defines = "e->name", uses = ["e"].
        let info = NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 10),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("e->name".into()),
                uses: vec!["e".into()],
                ..Default::default()
            },
            ..Default::default()
        };

        let (state, events) = transfer.apply(NodeIndex::new(0), &info, None, state);
        assert!(events.is_empty());
        assert_eq!(
            state.resource.get(sym_e),
            ResourceLifecycle::MOVED,
            "RHS local should transfer to MOVED (ownership handed to parent struct)"
        );
        assert_eq!(
            state.resource.get(sym_field),
            ResourceLifecycle::empty(),
            "field-LHS must NOT be seeded as a separately-tracked OPEN resource"
        );
    }

    /// Recall guard for the field-LHS gate: a plain local-to-local
    /// assignment (no field on the LHS) must still transfer the OPEN
    /// state to the new alias and mark the source MOVED, preserving
    /// existing local-leak detection.
    #[test]
    fn local_to_local_assignment_still_transfers_open() {
        let mut interner = SymbolInterner::new();
        let sym_buf = interner.intern("buf");
        let sym_cursor = interner.intern("cursor");

        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_buf, ResourceLifecycle::OPEN);

        // `cursor = buf`: plain alias, no field.
        let info = NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 10),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("cursor".into()),
                uses: vec!["buf".into()],
                ..Default::default()
            },
            ..Default::default()
        };

        let (state, events) = transfer.apply(NodeIndex::new(0), &info, None, state);
        assert!(events.is_empty());
        assert_eq!(state.resource.get(sym_buf), ResourceLifecycle::MOVED);
        assert_eq!(state.resource.get(sym_cursor), ResourceLifecycle::OPEN);
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        let info = NodeInfo {
            kind: StmtKind::If,
            condition_text: Some("(f)".into()),
            condition_vars: vec!["f".into()],
            condition_negated: false,
            null_check: Some(crate::cfg::NullCheck {
                var: "f".into(),
                null_on_true: false,
            }),
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        // `if (!f)`, condition_negated=true, true-edge means f is null
        let info = NodeInfo {
            kind: StmtKind::If,
            condition_text: Some("(!f)".into()),
            condition_vars: vec!["f".into()],
            condition_negated: true,
            null_check: Some(crate::cfg::NullCheck {
                var: "f".into(),
                null_on_true: true,
            }),
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

    #[test]
    fn condition_without_null_check_keeps_open() {
        // `if (f != g)` carries no null-check fact: neither edge may clear.
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };
        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);
        let info = NodeInfo {
            kind: StmtKind::If,
            condition_text: Some("(f != g)".into()),
            condition_vars: vec!["f".into(), "g".into()],
            ..Default::default()
        };
        for edge in [EdgeKind::True, EdgeKind::False] {
            let (out, _) = transfer.apply(NodeIndex::new(1), &info, Some(edge), state.clone());
            assert_eq!(out.resource.get(sym_f), ResourceLifecycle::OPEN);
        }
    }

    fn go_transfer(interner: &SymbolInterner) -> DefaultTransfer<'_> {
        DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        }
    }

    fn go_open_node() -> NodeInfo {
        // f, err := os.Open(p)
        NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                defines: Some("f".into()),
                extra_defines: vec!["err".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("os.Open".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn go_err_check_node() -> NodeInfo {
        // if err != nil
        NodeInfo {
            kind: StmtKind::If,
            condition_text: Some("err != nil".into()),
            condition_vars: vec!["err".into()],
            null_check: Some(crate::cfg::NullCheck {
                var: "err".into(),
                null_on_true: false,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn go_err_companion_clears_open_on_err_branch() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");
        interner.intern("err");
        let transfer = go_transfer(&interner);

        let (state, _) = transfer.apply(
            NodeIndex::new(0),
            &go_open_node(),
            None,
            ProductState::initial(),
        );
        assert_eq!(state.resource.get(sym_f), ResourceLifecycle::OPEN);

        let check = go_err_check_node();
        let (err_branch, _) = transfer.apply(
            NodeIndex::new(1),
            &check,
            Some(EdgeKind::True),
            state.clone(),
        );
        assert!(
            !err_branch
                .resource
                .get(sym_f)
                .contains(ResourceLifecycle::OPEN),
            "err != nil branch: os.Open failed, f holds nothing"
        );
        let (ok_branch, _) =
            transfer.apply(NodeIndex::new(1), &check, Some(EdgeKind::False), state);
        assert_eq!(ok_branch.resource.get(sym_f), ResourceLifecycle::OPEN);
    }

    #[test]
    fn go_err_companion_dropped_when_err_reassigned() {
        // f, err := os.Open(p); _, err = f.Write(b); if err != nil { ... }
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern("f");
        interner.intern("err");
        let transfer = go_transfer(&interner);

        let (state, _) = transfer.apply(
            NodeIndex::new(0),
            &go_open_node(),
            None,
            ProductState::initial(),
        );
        let write = NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                defines: Some("err".into()),
                uses: vec!["f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("f.Write".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _) = transfer.apply(NodeIndex::new(1), &write, None, state);
        let (err_branch, _) = transfer.apply(
            NodeIndex::new(2),
            &go_err_check_node(),
            Some(EdgeKind::True),
            state,
        );
        assert_eq!(
            err_branch.resource.get(sym_f),
            ResourceLifecycle::OPEN,
            "the Write error says nothing about the open handle"
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
    fn camel_case_matcher_is_found_as_a_whole_token() {
        // Conditions are lowercased before matching, so a camelCase matcher
        // such as Passport's `isAuthenticated` is compared in lowercase.
        assert!(condition_contains_auth_token(
            "req.isauthenticated()",
            "isAuthenticated"
        ));
        assert!(!condition_contains_auth_token(
            "req.notisauthenticatedcache()",
            "isAuthenticated"
        ));
    }

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

    // chain-receiver decomposition + chain_proxies tracking
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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

    // Pointer-analysis: PtrProxyHint::FieldOnly routes
    // single-dot proxy-acquire to chain_proxies, suppressing the
    // SymbolId path that would otherwise mark the field-aliased local
    // as a leakable resource.

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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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
            nonescaping_field_containers: None,
            closeable_wrappers: None,
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

    #[test]
    fn inner_call_release_in_arg_marks_closed() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern_scoped(None, "f");

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 30),
                ..Default::default()
            },
            taint: TaintMeta {
                uses: vec!["t".into(), "f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("require.NoError".into()),
                ..Default::default()
            },
            arg_callees: vec![None, Some("f.Close".into())],
            ..Default::default()
        };

        let (state, events) = transfer.apply(NodeIndex::new(0), &info, None, state);
        assert!(events.is_empty());
        assert_eq!(state.resource.get(sym_f), ResourceLifecycle::CLOSED);
    }

    #[test]
    fn inner_call_release_in_arg_chained_receiver_skipped() {
        let mut interner = SymbolInterner::new();
        let sym_c = interner.intern_scoped(None, "c");

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_c, ResourceLifecycle::OPEN);

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 30),
                ..Default::default()
            },
            taint: TaintMeta {
                uses: vec!["c".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("t.Helper".into()),
                ..Default::default()
            },
            arg_callees: vec![Some("c.mu.Unlock".into())],
            ..Default::default()
        };

        let (state, _) = transfer.apply(NodeIndex::new(0), &info, None, state);
        assert_eq!(state.resource.get(sym_c), ResourceLifecycle::OPEN);
    }

    #[test]
    fn inner_call_release_in_arg_respects_in_defer() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern_scoped(None, "f");

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let mut state = ProductState::initial();
        state.resource.set(sym_f, ResourceLifecycle::OPEN);

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 30),
                ..Default::default()
            },
            taint: TaintMeta {
                uses: vec!["f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("log.Print".into()),
                ..Default::default()
            },
            arg_callees: vec![Some("f.Close".into())],
            in_defer: true,
            ..Default::default()
        };

        let (state, _) = transfer.apply(NodeIndex::new(0), &info, None, state);
        assert_eq!(state.resource.get(sym_f), ResourceLifecycle::OPEN);
    }

    #[test]
    fn member_field_lhs_acquire_skips_resource_state() {
        let interner = SymbolInterner::new();

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 30),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("b.cpuprof".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("os.Create".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let (state, _) = transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
        assert!(state.resource.vars.is_empty());
    }

    #[test]
    fn bare_ident_lhs_acquire_still_tracks() {
        let mut interner = SymbolInterner::new();
        let sym_f = interner.intern_scoped(None, "f");

        let transfer = DefaultTransfer {
            lang: Lang::Go,
            resource_pairs: rules::resource_pairs(Lang::Go),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
            nonescaping_field_containers: None,
            closeable_wrappers: None,
        };

        let info = NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (0, 30),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("f".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("os.Open".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let (state, _) = transfer.apply(NodeIndex::new(0), &info, None, ProductState::initial());
        assert!(state.resource.get(sym_f).contains(ResourceLifecycle::OPEN));
    }
}
