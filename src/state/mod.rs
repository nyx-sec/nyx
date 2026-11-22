//! State-model analysis: resource lifecycle and authentication state tracking.
//!
//! Runs a per-function state machine over the CFG to detect use-after-close,
//! double-close, resource leaks, and unauthenticated access to privileged
//! operations.
//!
//! Enabled by default. Disable via `scanner.enable_state_analysis = false`.
//! Runs in `--mode full` and `--mode taint`; skipped in AST-only mode.
//!
//! # Rule IDs
//!
//! | Rule ID | Severity | What it detects |
//! |---------|----------|-----------------|
//! | `state-use-after-close` | High | Operation on a resource after it was closed |
//! | `state-double-close` | Medium | Resource closed twice |
//! | `state-resource-leak` | Medium | Resource opened and never closed on any path |
//! | `state-resource-leak-possible` | Low | Resource closed on some paths but not others |
//! | `state-unauthed-access` | High | Web handler reaches privileged sink without an auth call |
//!
//! # Managed-resource suppression
//!
//! Language-specific cleanup patterns suppress leak findings automatically:
//!
//! | Pattern | Languages |
//! |---------|-----------|
//! | RAII / Drop | Rust (all leak findings suppressed except `alloc`/`dealloc`) |
//! | Smart pointers (`make_unique`, `make_shared`) | C++ |
//! | `defer f.Close()` | Go |
//! | `with open(f) as f:` | Python |
//! | try-with-resources | Java |
//!
//! # Tracked acquire/release pairs
//!
//! C/C++: `fopen`/`fclose`, `open`/`close`, `socket`/`close`,
//! `malloc`/`free`, `pthread_mutex_lock`/`pthread_mutex_unlock`,
//! `new`/`delete`.
//!
//! Rust: `File::open`/`close`, `TcpStream::connect`/`shutdown`,
//! mutex `lock`/`read`/`write`/`drop`.
//!
//! Java: stream/connection/socket constructors / `close`, `getConnection`/`close`.
//!
//! Go, Python, JavaScript, Ruby, PHP follow language-idiomatic equivalents.
//!
//! # Submodules
//!
//! - [`domain`]: state lattice (`ResourceState`, `AuthState`, `StateCell`)
//! - [`engine`]: generic forward transfer engine (`Transfer` trait, `run_forward`)
//! - [`facts`]: per-node state fact extraction
//! - [`lattice`]: lattice join/meet for state values
//! - [`symbol`]: resource symbol normalisation
//! - [`transfer`]: `DefaultTransfer` — the concrete resource-lifecycle transfer function

pub mod domain;
pub mod engine;
pub mod facts;
pub mod lattice;
pub mod symbol;
pub mod transfer;

use crate::cfg::{Cfg, FuncSummaries};
use crate::cfg_analysis::rules;
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use domain::{AuthLevel, ProductState};
use engine::MAX_TRACKED_VARS;
use facts::StateFinding;
use petgraph::graph::NodeIndex;
use symbol::SymbolInterner;
use transfer::DefaultTransfer;

/// Classify decorator/annotation/attribute names against the language's auth
/// rules and return the resulting `AuthLevel`.  Any admin-like match produces
/// `Admin`; any generic auth match produces `Authed`; otherwise `Unauthed`.
pub fn classify_auth_decorators(lang: Lang, decorators: &[String]) -> AuthLevel {
    if decorators.is_empty() {
        return AuthLevel::Unauthed;
    }
    let auth_rules = rules::auth_rules(lang);
    let mut level = AuthLevel::Unauthed;
    for dec in decorators {
        let d = dec.to_ascii_lowercase();
        // Admin patterns, match the same static list used by the call-site
        // transfer so decorators and runtime checks agree on privilege.
        if d.contains("admin") || d.contains("hasrole") || d.contains("superuser") {
            return AuthLevel::Admin;
        }
        let matches = auth_rules.iter().any(|rule| {
            rule.matchers.iter().any(|m| {
                let ml = m.to_ascii_lowercase();
                d == ml || d.ends_with(&ml)
            })
        });
        if matches && level < AuthLevel::Authed {
            level = AuthLevel::Authed;
        }
    }
    level
}

/// Run state-model dataflow analysis on a single function's CFG.
///
/// Returns findings for use-after-close, double-close, resource leaks,
/// and unauthenticated access to sensitive sinks.
///
/// `path_safe_suppressed_sink_spans` lists CFG sink spans whose tainted
/// inputs were proved path-safe by the SSA taint engine.  When a
/// privileged sink at one of those spans is reached without
/// authentication, `state-unauthed-access` is suppressed: the taint
/// engine has already proved the user-controlled input cannot escape
/// into a privileged location, so the auth concern is structurally
/// reduced.
#[allow(clippy::too_many_arguments)]
pub fn run_state_analysis(
    cfg: &Cfg,
    entry: NodeIndex,
    lang: Lang,
    _source_bytes: &[u8],
    func_summaries: &FuncSummaries,
    _global_summaries: Option<&GlobalSummaries>,
    enable_auth: bool,
    resource_method_summaries: &[transfer::ResourceMethodSummary],
    auth_decorators: &[String],
    path_safe_suppressed_sink_spans: &std::collections::HashSet<(usize, usize)>,
    // Optional `var_name → PtrProxyHint` map derived from the body's
    // PointsToFacts.  When present, the proxy-acquire transfer suppresses
    // SymbolId attribution on field-aliased receivers (`m := c.mu;
    // m.Lock()`) and routes them through `chain_proxies` instead.  Pass
    // `None` to disable, strict-additive.
    ptr_proxy_hints: Option<&std::collections::HashMap<String, crate::pointer::PtrProxyHint>>,
    // Names of variables whose `.close()`/release calls live in a nested
    // closure (event handler, deferred callback) that the per-body CFG
    // can't observe directly.  Used to suppress resource-leak findings
    // for handles whose cleanup is registered as a callback (`ws.on(
    // "close", () => ws2.close())`).  Pass `None` for languages or
    // shapes that don't need this.
    closure_released_var_names: Option<&std::collections::HashSet<String>>,
) -> Vec<StateFinding> {
    let _span = tracing::debug_span!("run_state_analysis").entered();

    let interner = SymbolInterner::from_cfg_scoped(cfg);

    if interner.len() > MAX_TRACKED_VARS {
        tracing::warn!(
            symbols = interner.len(),
            max = MAX_TRACKED_VARS,
            "state analysis: too many variables, capping tracking"
        );
    }

    let resource_pairs = rules::resource_pairs(lang);
    // C/C++ struct-value containers whose field-acquire genuinely leaks
    // (a non-escaping stack struct) — lift the ownership-transfer
    // suppression for those.  Empty for other languages.
    let nonescaping_field_containers = transfer::nonescaping_local_field_containers(cfg, lang);
    // Java wrapper objects whose lifetime this body accounts for; a stream
    // handed to one of their constructors is owned by the wrapper.
    let closeable_wrappers = transfer::closeable_wrapper_names(cfg, lang);
    let transfer = DefaultTransfer {
        lang,
        resource_pairs,
        interner: &interner,
        resource_method_summaries,
        ptr_proxy_hints,
        nonescaping_field_containers: Some(&nonescaping_field_containers),
        closeable_wrappers: Some(&closeable_wrappers),
    };

    // Seed initial auth level from decorator-based authorization markers.
    // Functions tagged with an auth decorator/annotation/attribute start in
    // `Authed` (or `Admin`) instead of `Unauthed`, so the privileged-sink
    // check in `extract_findings` suppresses findings framework-level auth
    // already enforces.
    let mut initial = ProductState::initial();
    initial.auth.auth_level = classify_auth_decorators(lang, auth_decorators);
    let result = engine::run_forward(cfg, entry, &transfer, initial);

    facts::extract_findings(
        &result,
        cfg,
        &interner,
        lang,
        func_summaries,
        enable_auth,
        path_safe_suppressed_sink_spans,
        closure_released_var_names,
    )
}

/// Build a per-body map of variable names whose release calls
/// (`.close`, `.destroy`, `.end`, `.release`, …) appear inside a
/// **descendant** body (a closure / event handler nested inside the
/// body that opens the handle).
///
/// Returned: `body_id → set of var names released somewhere inside
/// that body's nested-closure subtree`.  Used by the structural
/// ResourceMisuse pass and the state-model leak pass to suppress
/// findings whose cleanup lives in a callback the per-body CFG can't
/// follow (`socket.on("close", () => ws.close())`).
///
/// Restricted to descendants — sibling methods on the same class
/// don't share resource ownership, so a release in `queryAndClose`
/// must NOT silence a leak in sibling `queryAndLeak`.  Only true
/// nested-closure parent / child relationships participate.
pub fn collect_closure_released_var_names(
    bodies: &[crate::cfg::BodyCfg],
    lang: Lang,
) -> std::collections::HashMap<crate::cfg::BodyId, std::collections::HashSet<String>> {
    use crate::cfg::{BodyId, StmtKind};
    use petgraph::visit::IntoNodeReferences;

    // Step 1: collect releases per body.  Only nested (non-toplevel)
    // closures are eligible — top-level bodies' own releases are
    // already tracked by the dataflow.
    let pairs = rules::resource_pairs(lang);
    let mut per_body: std::collections::HashMap<BodyId, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    for body in bodies {
        if body.meta.parent_body_id.is_none() {
            continue;
        }
        let mut local = std::collections::HashSet::new();
        for (_idx, info) in body.graph.node_references() {
            if info.kind != StmtKind::Call {
                continue;
            }
            let Some(callee) = info.call.callee.as_deref() else {
                continue;
            };
            let cl = callee.to_ascii_lowercase();
            let is_release = pairs.iter().any(|p| {
                p.release.iter().any(|r| {
                    let rl = r.to_ascii_lowercase();
                    if let Some(method) = rl.strip_prefix('.') {
                        cl.ends_with(&format!(".{method}"))
                    } else {
                        cl == rl || cl.ends_with(&format!(".{rl}"))
                    }
                })
            });
            if !is_release {
                continue;
            }
            if let Some(rcv) = info.call.receiver.as_deref() {
                local.insert(rcv.to_string());
            } else if let Some((rcv, _)) = callee.rsplit_once('.')
                && !rcv.is_empty()
            {
                local.insert(rcv.to_string());
            }
        }
        if !local.is_empty() {
            per_body.insert(body.meta.id, local);
        }
    }

    // Step 1b: receiver fields released by a sibling method.  A handle
    // stored on the object (`self.fh = open(p)`) belongs to the object, and
    // a method of the same class that releases that field
    // (`def close(self): self.fh.close()`) is where it is closed.  Unlike
    // plain locals, receiver fields are shared between sibling methods, so
    // the release counts for every method of the class.  A class with no
    // such method keeps the leak.  JS / TS are left out: their class-field
    // acquire is reported on purpose (see
    // `transfer::acquire_into_field_transfers_ownership`).
    let mut sibling_field_releases: std::collections::HashMap<
        BodyId,
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();
    if matches!(lang, Lang::Python | Lang::Php | Lang::Ruby) {
        for body in bodies {
            let Some(class_id) = body.meta.parent_body_id else {
                continue;
            };
            for (_idx, info) in body.graph.node_references() {
                if info.kind != StmtKind::Call {
                    continue;
                }
                let Some(callee) = info.call.callee.as_deref() else {
                    continue;
                };
                let cl = callee.to_ascii_lowercase();
                let is_release = pairs.iter().any(|p| {
                    p.release
                        .iter()
                        .any(|r| transfer::callee_matches_pub(&cl, r))
                });
                if !is_release {
                    continue;
                }
                // Method form `self.fh.close()` / `$this->conn->close()`:
                // the receiver chain.  Function form `os.close(self.fd)`:
                // the first argument.
                let mut candidates: Vec<&str> = Vec::new();
                if let Some((rcv, _)) = callee.rsplit_once('.') {
                    candidates.push(rcv);
                } else if let Some(first) = info.call.arg_uses.first() {
                    candidates.extend(first.iter().map(String::as_str));
                }
                for c in candidates {
                    if let Some(field) = receiver_field_name(c) {
                        sibling_field_releases
                            .entry(class_id)
                            .or_default()
                            .insert(field);
                    }
                }
            }
        }
    }

    // Step 2: roll up into ancestor bodies.  Walk each non-top body's
    // parent chain and union its release set into every ancestor's
    // entry.  Class methods at the same nesting level (siblings under a
    // class body) do not roll up into each other — they have distinct
    // BodyId entries and the chain only flows through `parent_body_id`.
    let mut rollup: std::collections::HashMap<BodyId, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    let by_id: std::collections::HashMap<BodyId, &crate::cfg::BodyCfg> =
        bodies.iter().map(|b| (b.meta.id, b)).collect();
    for body in bodies {
        let Some(local) = per_body.get(&body.meta.id) else {
            continue;
        };
        let mut cur = body.meta.parent_body_id;
        while let Some(pid) = cur {
            rollup.entry(pid).or_default().extend(local.iter().cloned());
            cur = by_id.get(&pid).and_then(|b| b.meta.parent_body_id);
        }
    }
    for body in bodies {
        if let Some(class_id) = body.meta.parent_body_id
            && let Some(fields) = sibling_field_releases.get(&class_id)
        {
            rollup
                .entry(body.meta.id)
                .or_default()
                .extend(fields.iter().cloned());
        }
    }
    rollup
}

/// A field on the method's own receiver (`self.x`, `this.x`, `@x`, PHP
/// `$this->x`), spelled the way the CFG names its define (`this.x` for
/// PHP).  `None` for anything else.
fn receiver_field_name(name: &str) -> Option<String> {
    let (prefix, rest) = [
        ("self.", "self."),
        ("this.", "this."),
        ("$this->", "this."),
        ("@", "@"),
    ]
    .into_iter()
    .find_map(|(spelled, canonical)| name.strip_prefix(spelled).map(|r| (canonical, r)))?;
    let plain = !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    plain.then(|| format!("{prefix}{rest}"))
}

/// Names local to `body`: its parameters and the plain variables it assigns,
/// minus assignments the CFG marked as stores to storage the body does not
/// declare (Java / C++ unqualified members, Go package vars).
fn body_local_names(body: &crate::cfg::BodyCfg) -> std::collections::HashSet<&str> {
    let plain = |n: &str| {
        !n.is_empty()
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
    };
    let mut locals: std::collections::HashSet<&str> =
        body.meta.params.iter().map(String::as_str).collect();
    for info in body.graph.node_weights() {
        if let Some(d) = info.taint.defines.as_deref()
            && !info.escaping_store
            && plain(d)
        {
            locals.insert(d);
        }
        locals.extend(
            info.taint
                .extra_defines
                .iter()
                .map(String::as_str)
                .filter(|d| plain(d)),
        );
    }
    locals
}

/// Whether `name` is state owned by the method's receiver rather than a
/// local of the method body: `self.x` / `this.x` / `$this->x` / `@x`, the
/// receiver itself, a Go field path on a name the method neither declares
/// nor takes as a parameter (its named receiver), or a Java / C++ member
/// reached without `this`.
fn names_receiver_state(lang: Lang, name: &str, locals: &std::collections::HashSet<&str>) -> bool {
    if name.starts_with('@') {
        return true;
    }
    let name = name.trim_start_matches('$');
    let root_end = name
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(name.len());
    let root = &name[..root_end];
    if root.is_empty() {
        return false;
    }
    if matches!(root, "self" | "this") {
        return true;
    }
    if locals.contains(root) || locals.contains(name) {
        return false;
    }
    match lang {
        Lang::Go => root_end < name.len(),
        Lang::Java | Lang::Cpp => true,
        _ => false,
    }
}

/// Summaries for a C function whose body passes one of its own parameters,
/// bare, to a release call (`free(p)`, `fclose(f)`): calling it hands that
/// argument position to the release.
fn push_param_release_summaries(
    body: &crate::cfg::BodyCfg,
    name: &str,
    out: &mut Vec<transfer::ResourceMethodSummary>,
) {
    use petgraph::visit::IntoNodeReferences;
    let pairs = rules::resource_pairs(Lang::C);
    for (_, info) in body.graph.node_references() {
        if info.kind != crate::cfg::StmtKind::Call {
            continue;
        }
        let Some(callee) = info.call.callee.as_deref() else {
            continue;
        };
        let callee = callee.to_ascii_lowercase();
        if !pairs.iter().any(|p| {
            p.release
                .iter()
                .any(|r| transfer::callee_matches_pub(&callee, r))
        }) {
            continue;
        }
        for (i, uses) in info.call.arg_uses.iter().enumerate() {
            // Only an argument that is exactly the parameter releases it.
            // `free(*out)`, `free(p->buf)` and `free(&p)` release something
            // the parameter points at or holds, not the caller's handle.
            if i >= 64 || info.call.arg_bare_names & (1u64 << i) == 0 || uses.len() != 1 {
                continue;
            }
            for arg in uses {
                if let Some(k) = body.meta.params.iter().position(|p| p == arg)
                    && !out.iter().any(|s| {
                        s.method_name == name
                            && s.effect == transfer::ResourceEffect::ReleaseParam(k)
                    })
                {
                    out.push(transfer::ResourceMethodSummary {
                        method_name: name.to_string(),
                        effect: transfer::ResourceEffect::ReleaseParam(k),
                        class_group: body.meta.id,
                        original_span: info.ast.span,
                    });
                }
            }
        }
    }
}

/// Build resource method summaries by pre-scanning all method bodies for known
/// resource acquire/release operations. Only creates summaries for methods whose
/// bodies actually contain matching operations, never infers from names alone.
///
/// A summary stands for "calling this method opens / closes its receiver", so
/// only operations on receiver state count (see `names_receiver_state`).  A
/// function that opens and closes a local handle (`func write(p string) { f,
/// _ := os.Create(p); ..; f.Close() }`) says nothing about the receiver of a
/// same-named call elsewhere (`buf.Write(..)`).
pub fn build_resource_method_summaries(
    bodies: &[crate::cfg::BodyCfg],
    lang: Lang,
) -> Vec<transfer::ResourceMethodSummary> {
    use petgraph::visit::IntoNodeReferences;

    let resource_pairs = rules::resource_pairs(lang);
    let mut summaries = Vec::new();

    for body in bodies {
        let method_name = match &body.meta.name {
            Some(name) => name.clone(),
            None => continue,
        };
        // C has no methods: a function that frees one of its parameters.
        if lang == Lang::C {
            push_param_release_summaries(body, &method_name, &mut summaries);
            continue;
        }
        let class_group = match body.meta.parent_body_id {
            Some(pid) => pid,
            None => continue, // top-level functions are not class methods
        };
        let locals = body_local_names(body);
        let is_receiver_state = |name: &str| names_receiver_state(lang, name, &locals);

        for (_, info) in body.graph.node_references() {
            // Check both Call and Seq (Assignment) nodes, resource operations
            // can appear as RHS of assignments (e.g., `this.fd = fs.openSync(...)`).
            if !matches!(
                info.kind,
                crate::cfg::StmtKind::Call | crate::cfg::StmtKind::Seq
            ) {
                continue;
            }
            // Skip acquires whose lifetime is bounded by a managed cleanup
            // scope (Python `with`, Java try-with-resources, Ruby
            // File.open-with-block, Rust RAII).  The acquired handle is
            // released before the method returns, so propagating an
            // Acquire effect onto the caller's receiver creates an FP
            // class where callers of `def foo(self): with open(...): ...`
            // are flagged as leaking the receiver.
            if info.managed_resource {
                continue;
            }
            let callee = match &info.call.callee {
                Some(c) => c.to_ascii_lowercase(),
                None => continue,
            };
            for pair in resource_pairs {
                if pair
                    .acquire
                    .iter()
                    .any(|a| transfer::acquire_callee_matches(lang, &callee, a))
                {
                    // The receiver-proxy mechanism (state/transfer.rs)
                    // matches a method-name summary against `recv.method()`
                    // call sites and marks the receiver as OPEN.  This is
                    // only meaningful when the acquire binds a resource into
                    // receiver state (`self.fd = open(...)`, `this.fd =
                    // fs.openSync(...)`).  Acquires with no binding (`return
                    // open(...)`) or with a local binding (`f = open(...);
                    // f.close()`) do not transfer ownership onto the
                    // caller's receiver.
                    if info.taint.defines.as_deref().is_some_and(is_receiver_state) {
                        summaries.push(transfer::ResourceMethodSummary {
                            method_name: method_name.clone(),
                            effect: transfer::ResourceEffect::Acquire,
                            class_group,
                            original_span: info.ast.span,
                        });
                    }
                }
                // Release of receiver state: the method-call receiver
                // (`self.fh.close()`, `c.conn.Close()`) or, for the function
                // form, the first argument (`fs.closeSync(this.fd)`,
                // `os.close(self.fd)`).
                let releases_receiver_state = || {
                    let method_receiver = info.call.receiver.as_deref().into_iter().chain(
                        info.call
                            .callee
                            .as_deref()
                            .and_then(|c| c.rsplit_once('.'))
                            .map(|(r, _)| r),
                    );
                    let first_arg = info.call.arg_uses.first().into_iter().flatten();
                    method_receiver
                        .chain(first_arg.map(String::as_str))
                        .any(is_receiver_state)
                };
                if pair
                    .release
                    .iter()
                    .any(|r| transfer::callee_matches_pub(&callee, r))
                    && releases_receiver_state()
                {
                    summaries.push(transfer::ResourceMethodSummary {
                        method_name: method_name.clone(),
                        effect: transfer::ResourceEffect::Release,
                        class_group,
                        original_span: info.ast.span,
                    });
                }
            }
        }
    }
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_state_names() {
        let locals: std::collections::HashSet<&str> = ["f", "buf", "in", "self"].into();
        let rs = |lang, name| names_receiver_state(lang, name, &locals);
        // Explicit receiver spellings.
        assert!(rs(Lang::Python, "self.fh"));
        assert!(rs(Lang::JavaScript, "this.fd"));
        assert!(rs(Lang::Php, "$this->fh"));
        assert!(rs(Lang::Php, "this.fh"));
        assert!(rs(Lang::Ruby, "@file"));
        // Locals, params and modules are not receiver state.
        assert!(!rs(Lang::Python, "f"));
        assert!(!rs(Lang::Python, "app.db"));
        assert!(!rs(Lang::JavaScript, "fs"));
        assert!(!rs(Lang::Java, "in"));
        assert!(!rs(Lang::Go, "buf.inner"));
        // Go: a field path on the named receiver (never declared locally).
        assert!(rs(Lang::Go, "c.conn"));
        assert!(!rs(Lang::Go, "os"));
        // Java / C++ members reached without `this`.
        assert!(rs(Lang::Java, "conn"));
        assert!(rs(Lang::Cpp, "fd_"));
    }
}
