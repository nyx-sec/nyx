//! Gitea `web.Router` closure-nested route-group extractor.
//!
//! Gitea does not use gin/echo/net-http-mux; its HTTP layer is the
//! project-local router `code.gitea.io/gitea/modules/web` (`web.Router`).
//! Routes are registered on a single receiver `r` inside *closures*
//! passed to `r.Group(path, func() { … }, ...trailingMiddleware)` — the
//! group scoping is **lexical** (every route registered inside the
//! closure body inherits the group's trailing middleware), not
//! binding-based like gin's `g := r.Group(...); g.GET(...)`.  The
//! [`gin`](super::gin) extractor only understands the binding form, so
//! gitea's group middleware was dropped and every id/name-scoped DAO
//! read inside a handler fired `go.auth.missing_ownership_check`.
//!
//! Shape (routers/api/packages/api.go):
//! ```go
//! r.Group("/{username}", func() {
//!     r.Group("/container", func() {
//!         r.Get("/blobs/{uuid}", GetBlobsUpload)
//!     }, reqPackageAccess(perm.AccessModeRead))
//! })
//! ```
//! The trailing `reqPackageAccess(perm.AccessModeRead)` is a middleware
//! factory whose returned closure performs the ownership check
//! `if ctx.Package.AccessMode < accessMode && !ctx.IsUserSiteAdmin() { … }`.
//!
//! This extractor:
//! 1. walks the closure tree carrying a lexical stack of group
//!    middleware + accumulated path prefix,
//! 2. registers each `r.<Verb>(path, ...mw, handler)` /
//!    `r.Methods("V1,V2", path, ...mw, handler)` route with the
//!    accumulated middleware, and
//! 3. injects group/inline middleware as route-level auth checks onto
//!    the handler unit — recognising a middleware call as an ownership
//!    guard **by its factory body** (a closure reading a request-context
//!    permission field such as `ctx.Repo.Permission` / `ctx.Package.AccessMode`
//!    / `ctx.IsUserSiteAdmin` and emitting a `ctx.*Error` on failure),
//!    not by a hardcoded name list.  This generalises across gitea's
//!    whole `req*` family (`reqRepoReader`, `reqAdmin`, `reqOwner`, …)
//!    and correctly *excludes* feature gates like `reqStarsEnabled`
//!    (which read `setting.*`, not a `ctx.*` permission field).
//!
//! **Cross-file handlers.**  Gitea references handlers cross-package
//! (`container.GetBlobsUpload`), so the handler unit lives in another
//! file and the same-file `attach_route_handler` injection cannot reach
//! it.  BUT the authorization decision is same-file: the guard factory is
//! colocated with the registration.  [`extract_route_handler_auth_edges`]
//! harvests a [`CallerScopeEdge`] per route (keyed by handler leaf,
//! authorized iff the enclosing group is an ownership guard); the
//! existing cross-file caller-scope plumbing then lifts the `Ownership`
//! check onto the (other-file) handler unit.  Requires `--index off` (the
//! two-pass in-memory path), matching the caller-scope limitation.

use super::AuthExtractor;
use super::common::{
    ResolvedHandler, attach_route_handler, auth_check_from_call_site, call_site_from_node,
    http_method_from_name, is_handler_reference, join_route_paths, member_target, named_children,
    push_route_registration, string_literal_value, text,
};
use crate::auth_analysis::caller_scope::CallerScopeEdge;
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{
    AuthCheck, AuthCheckKind, AuthorizationModel, CallSite, Framework,
};
use crate::symbol::Lang;
use crate::utils::project::FrameworkContext;
use std::path::Path;
use tree_sitter::{Node, Tree};

/// Request-context field/method leaves that carry *authority* (not mere
/// identity).  A middleware factory whose closure reads one of these
/// rooted at the request-context parameter is performing an ownership /
/// permission check.  `ctx.Doer` (identity only) is deliberately
/// excluded — it proves *who* the caller is, not *what* they may touch.
const PERMISSION_FIELDS: &[&str] = &[
    "AccessMode",
    "Permission",
    "CanRead",
    "CanWrite",
    "CanCreate",
    "CanUse",
    "CanWriteToBranch",
    "IsUserSiteAdmin",
    "IsUserRepoAdmin",
    "IsUserRepoWriter",
    "IsUserRepoOwner",
    "IsOwner",
    "IsAdmin",
];

/// Request-context error emitters.  A guard both *reads* an authority
/// field and *rejects* on failure; requiring an error-emit alongside the
/// permission read excludes context-setup helpers (`PackageContexter`,
/// `PackageAssignment`) that merely populate `ctx.Package` without
/// gating.
const CTX_ERROR_METHODS: &[&str] = &[
    "HTTPError",
    "APIError",
    "APIErrorNotFound",
    "Error",
    "NotFound",
    "ServerError",
    "JSONError",
    "Forbidden",
];

pub struct GiteaExtractor;

impl AuthExtractor for GiteaExtractor {
    fn supports(&self, lang: &str, _framework_ctx: Option<&FrameworkContext>) -> bool {
        // Gate only on language; the walk is a no-op on Go files that do
        // not use the closure-group form (a `Group` call with a
        // `func_literal` argument), so gin/echo files pass through
        // untouched without needing a framework signal.
        lang == "go"
    }

    fn extract(
        &self,
        tree: &Tree,
        bytes: &[u8],
        path: &Path,
        rules: &AuthAnalysisRules,
        model: &mut AuthorizationModel,
    ) {
        let root = tree.root_node();
        walk_routes(root, root, &[], "", bytes, path, rules, model);
    }
}

/// Harvest cross-file route→handler authorization edges from a gitea
/// `web.Router` file.
///
/// Gitea registers handlers cross-package
/// (`r.Get("/blobs/{uuid}", container.GetBlobsUpload)`), so the handler
/// unit lives in another file and [`GiteaExtractor::extract`]'s
/// same-file `attach_route_handler` injection cannot reach it.  BUT the
/// *authorization decision* is same-file: the ownership-guard middleware
/// factory (`reqPackageAccess`, `reqRepoReader`, …) is colocated with the
/// route registration in `api.go`, so `middleware_is_ownership_guard`
/// resolves it here.
///
/// This emits a [`CallerScopeEdge`] per route, keyed by the handler leaf
/// name, with `caller_authorized = true` (carrying a route-level
/// `Ownership` check) when the enclosing group / inline middleware is an
/// ownership guard, `false` otherwise.  The existing cross-file
/// caller-scope plumbing folds these into `GlobalSummaries` and
/// [`crate::auth_analysis::caller_scope::apply_cross_file_caller_scope`]
/// lifts the `Ownership` check onto the (other-file) handler unit — but
/// only when EVERY registration of that leaf is authorized (a handler
/// registered both guarded and bare stays unauthorized, preserving the
/// real attack surface).
pub fn extract_route_handler_auth_edges(
    tree: &Tree,
    bytes: &[u8],
    lang: Lang,
) -> Vec<CallerScopeEdge> {
    // Fast path: a gitea route→handler edge is emitted only from inside a
    // `<r>.Group(...)` / `<r>.PathGroup(...)` closure group — `harvest_edges`
    // never pushes an edge until `in_group` is set, which requires a matched
    // `Group` / `PathGroup` method call (both names contain the substring
    // `Group`).  A Go file with no `Group` token therefore cannot produce an
    // edge, so skip the whole-tree walk.  Cheap byte-substring pre-filter,
    // mirroring the dynamic framework adapters' `file_bytes.windows(..).any(..)`
    // idiom; a spurious match (e.g. `sync.WaitGroup`) only costs the walk we
    // would otherwise have done, so this never drops a real edge.
    if super::common::auth_walk_gate_enabled()
        && !bytes.windows(b"Group".len()).any(|w| w == b"Group")
    {
        return Vec::new();
    }
    let root = tree.root_node();
    let mut edges = Vec::new();
    harvest_edges(root, root, false, false, bytes, lang, &mut edges);
    edges
}

/// Recursive descent tracking (a) whether we are lexically INSIDE a
/// closure-form group (`in_group`) and (b) whether an enclosing group is
/// ownership-guarded (`guarded`).  Emits one edge per verb route — but
/// ONLY for routes inside a closure group.
///
/// The `in_group` gate is a soundness restriction: a top-level
/// `router.GET(path, handler)` (gin / echo / chi / net-http) is NOT a
/// gitea `web.Router` closure route, and emitting an (unauthorized) edge
/// for its handler leaf would poison any legitimate caller-scope lift of
/// a same-named helper elsewhere.  gitea's ownership guards live on
/// closure groups, so every route we care about is `in_group`; skipping
/// out-of-group routes loses no gitea recall and avoids cross-framework
/// collateral.
#[allow(clippy::too_many_arguments)]
fn harvest_edges(
    root: Node<'_>,
    node: Node<'_>,
    in_group: bool,
    guarded: bool,
    bytes: &[u8],
    lang: Lang,
    edges: &mut Vec<CallerScopeEdge>,
) {
    if node.kind() == "call_expression"
        && let Some(function) = node.child_by_field_name("function")
        && let Some((_object, method)) = member_target(function, bytes)
    {
        if matches!(method.as_str(), "Group" | "PathGroup")
            && let Some(group) = parse_closure_group(node, bytes)
        {
            let group_guarded = group
                .middleware
                .iter()
                .any(|mw| middleware_is_ownership_guard(root, &mw.name, bytes));
            harvest_edges(
                root,
                group.closure_body,
                true,
                guarded || group_guarded,
                bytes,
                lang,
                edges,
            );
            return;
        }

        let path_arg_idx = if http_method_from_name(&method)
            .is_some_and(|m| m != crate::auth_analysis::model::HttpMethod::Use)
        {
            Some(0)
        } else if matches!(method.as_str(), "Methods" | "MatchPath") {
            Some(1)
        } else {
            None
        };

        if let Some(path_arg_idx) = path_arg_idx
            && in_group
            && let Some(edge) = route_handler_edge(root, node, guarded, path_arg_idx, bytes, lang)
        {
            edges.push(edge);
            return;
        }
    }

    for child in named_children(node) {
        harvest_edges(root, child, in_group, guarded, bytes, lang, edges);
    }
}

/// Build a caller-scope edge for a single verb route registration.
fn route_handler_edge(
    root: Node<'_>,
    node: Node<'_>,
    guarded: bool,
    path_arg_idx: usize,
    bytes: &[u8],
    lang: Lang,
) -> Option<CallerScopeEdge> {
    let arguments = node.child_by_field_name("arguments")?;
    let args = named_children(arguments);
    // Confirm arg[path_arg_idx] is the route-path literal (skip
    // non-route calls that happen to share a verb-like method name).
    string_literal_value(*args.get(path_arg_idx)?, bytes)?;
    let (handler_idx, handler_expr) = args
        .iter()
        .enumerate()
        .rev()
        .find(|(idx, arg)| *idx > path_arg_idx && is_handler_reference(**arg))?;
    let handler_leaf = handler_reference_leaf(*handler_expr, bytes)?;

    // Inline middleware between the path and the handler can also carry
    // the ownership guard.
    let inline_guarded = args[path_arg_idx + 1..handler_idx]
        .iter()
        .any(|a| middleware_is_ownership_guard(root, &call_site_from_node(*a, bytes).name, bytes));
    let authorized = guarded || inline_guarded;

    let route_checks = if authorized {
        vec![AuthCheck {
            kind: AuthCheckKind::Ownership,
            callee: "gitea group ownership guard".to_string(),
            subjects: Vec::new(),
            span: span_of(node),
            line: node.start_position().row + 1,
            args: Vec::new(),
            condition_text: None,
            is_route_level: true,
            dominates_body: false,
        }]
    } else {
        Vec::new()
    };

    Some(CallerScopeEdge {
        lang,
        callee_leaf: handler_leaf,
        caller_authorized: authorized,
        route_checks,
    })
}

/// Leaf name of a handler reference: `container.GetBlobsUpload` →
/// `GetBlobsUpload`, `GetBlobsUpload` → `GetBlobsUpload`.  Function
/// literals (inline closures) have no leaf and are skipped (they carry
/// their own body; there is no separate unit to lift onto).
fn handler_reference_leaf(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(text(node, bytes)),
        "selector_expression" => node.child_by_field_name("field").map(|f| text(f, bytes)),
        _ => None,
    }
}

fn span_of(node: Node<'_>) -> (usize, usize) {
    (node.start_byte(), node.end_byte())
}

/// Recursive descent carrying the active group-middleware stack and the
/// accumulated path prefix.  Closure-form groups extend the stack while
/// recursing into their closure body; verb calls register a route with
/// the current stack + inline middleware.
#[allow(clippy::too_many_arguments)]
fn walk_routes(
    root: Node<'_>,
    node: Node<'_>,
    mw_stack: &[CallSite],
    path_prefix: &str,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    if node.kind() == "call_expression"
        && let Some(function) = node.child_by_field_name("function")
        && let Some((_object, method)) = member_target(function, bytes)
    {
        // Closure-form group: `<r>.Group(path, func() { … }, ...trailing)`
        // or `<r>.PathGroup("/*", func(g) { … }, ...trailing)`.
        if matches!(method.as_str(), "Group" | "PathGroup")
            && let Some(group) = parse_closure_group(node, bytes)
        {
            let mut new_stack = mw_stack.to_vec();
            new_stack.extend(group.middleware);
            let new_prefix = join_route_paths(path_prefix, &group.path_prefix);
            walk_routes(
                root,
                group.closure_body,
                &new_stack,
                &new_prefix,
                bytes,
                path,
                rules,
                model,
            );
            return;
        }

        // Verb route: `<r>.Get(path, ...mw, handler)`.
        if let Some(http_method) = http_method_from_name(&method)
            && http_method != crate::auth_analysis::model::HttpMethod::Use
        {
            register_route(
                root,
                node,
                mw_stack,
                path_prefix,
                0,
                bytes,
                path,
                rules,
                model,
            );
            return;
        }

        // Verb-list route: `<r>.Methods("HEAD,GET", path, ...mw, handler)`
        // / `<g>.MatchPath("PUT", "/x", ...mw, handler)`.  The verb list
        // is arg 0; the path is arg 1.
        if matches!(method.as_str(), "Methods" | "MatchPath") {
            register_route(
                root,
                node,
                mw_stack,
                path_prefix,
                1,
                bytes,
                path,
                rules,
                model,
            );
            return;
        }
    }

    for child in named_children(node) {
        walk_routes(
            root,
            child,
            mw_stack,
            path_prefix,
            bytes,
            path,
            rules,
            model,
        );
    }
}

struct ClosureGroup<'tree> {
    path_prefix: String,
    middleware: Vec<CallSite>,
    closure_body: Node<'tree>,
}

/// Parse `<r>.Group(pathLit, func() { … }, ...trailingMiddleware)`.
/// Returns `None` for gin's binding form (`r.Group(path, mw)` with no
/// `func_literal` argument), leaving those to the gin extractor.
fn parse_closure_group<'tree>(node: Node<'tree>, bytes: &[u8]) -> Option<ClosureGroup<'tree>> {
    let arguments = node.child_by_field_name("arguments")?;
    let args = named_children(arguments);
    let closure_pos = args.iter().position(|a| a.kind() == "func_literal")?;
    let closure = args[closure_pos];
    let closure_body = closure.child_by_field_name("body")?;

    let path_prefix = args
        .iter()
        .take(closure_pos)
        .find_map(|a| string_literal_value(*a, bytes))
        .unwrap_or_default();

    // Trailing args after the closure are group-scoped middleware.
    let middleware = args[closure_pos + 1..]
        .iter()
        .map(|a| call_site_from_node(*a, bytes))
        .collect();

    Some(ClosureGroup {
        path_prefix,
        middleware,
        closure_body,
    })
}

/// Register a verb route.  `path_arg_idx` is the positional index of the
/// route-path string literal (1 for `Get(path, …)`, 2 for
/// `Methods(verbs, path, …)`).  Middleware = accumulated group stack +
/// inline args between the path and the handler.
#[allow(clippy::too_many_arguments)]
fn register_route(
    root: Node<'_>,
    node: Node<'_>,
    mw_stack: &[CallSite],
    path_prefix: &str,
    path_arg_idx: usize,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let args = named_children(arguments);
    let Some(route_path) = args
        .get(path_arg_idx)
        .and_then(|p| string_literal_value(*p, bytes))
    else {
        return;
    };
    // The handler is the last handler-reference argument.
    let Some((handler_idx, handler_expr)) = args
        .iter()
        .enumerate()
        .rev()
        .find(|(idx, arg)| *idx > path_arg_idx && is_handler_reference(**arg))
    else {
        return;
    };
    let full_path = join_route_paths(path_prefix, &route_path);
    let Some(handler) = attach_route_handler(
        root,
        *handler_expr,
        format!("gitea {full_path}"),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    // Accumulated group middleware + inline middleware (args strictly
    // between the path and the handler).
    let mut middleware_calls = mw_stack.to_vec();
    for inline in &args[path_arg_idx + 1..handler_idx] {
        middleware_calls.push(call_site_from_node(*inline, bytes));
    }

    inject_gitea_middleware_auth(model, &handler, root, &middleware_calls, rules, bytes);

    push_route_registration(
        model,
        Framework::Gin,
        // `Methods("HEAD,GET", …)` registers several verbs; the concrete
        // list is cosmetic for the ownership check (which operates on the
        // handler unit, not the route), so record the group as `All`.
        crate::auth_analysis::model::HttpMethod::All,
        full_path,
        path,
        handler,
        middleware_calls,
    );
}

/// Inject recognised middleware as **route-level** auth checks onto the
/// handler unit.  A middleware call is recognised either by the shared
/// name-based [`auth_check_from_call_site`] classifier, or — for gitea's
/// project-local `req*` factories — by its factory body (see
/// [`middleware_is_ownership_guard`]).
fn inject_gitea_middleware_auth(
    model: &mut AuthorizationModel,
    handler: &ResolvedHandler,
    root: Node<'_>,
    middleware_calls: &[CallSite],
    rules: &AuthAnalysisRules,
    bytes: &[u8],
) {
    let Some(unit) = model.units.get_mut(handler.unit_idx) else {
        return;
    };
    for call in middleware_calls {
        if let Some(mut check) = auth_check_from_call_site(call, handler.line, rules) {
            check.is_route_level = true;
            unit.auth_checks.push(check);
        } else if middleware_is_ownership_guard(root, &call.name, bytes) {
            unit.auth_checks.push(AuthCheck {
                kind: AuthCheckKind::Ownership,
                callee: call.name.clone(),
                subjects: Vec::new(),
                span: call.span,
                line: handler.line,
                args: call.args.clone(),
                condition_text: None,
                is_route_level: true,
                dominates_body: false,
            });
        }
    }
}

/// Recognise a middleware factory as an ownership guard by its body: the
/// closure it returns (or the function itself, if it is the handler)
/// reads an authority-bearing field rooted at the request-context param
/// AND emits a `ctx.*Error` on the failure branch.
fn middleware_is_ownership_guard(root: Node<'_>, callee_name: &str, bytes: &[u8]) -> bool {
    // Bare identifiers only (`reqPackageAccess`); package-qualified
    // (`context.Foo`) resolves cross-file and is out of same-file scope.
    if callee_name.contains('.') || callee_name.is_empty() {
        return false;
    }
    let Some(func_decl) = find_top_level_go_func(root, callee_name, bytes) else {
        return false;
    };
    let (guard_body, ctx_param) = guard_closure_and_ctx(func_decl, bytes);
    let Some(guard_body) = guard_body else {
        return false;
    };

    let mut reads_permission = false;
    let mut emits_error = false;
    let mut stack = vec![guard_body];
    while let Some(n) = stack.pop() {
        if n.kind() == "selector_expression"
            && let Some(field) = n.child_by_field_name("field").map(|f| text(f, bytes))
            && let Some(rootid) = selector_root_ident(n, bytes)
            && rootid == ctx_param
        {
            if PERMISSION_FIELDS.contains(&field.as_str()) {
                reads_permission = true;
            }
            if CTX_ERROR_METHODS.contains(&field.as_str()) {
                emits_error = true;
            }
        }
        if reads_permission && emits_error {
            return true;
        }
        for child in named_children(n) {
            stack.push(child);
        }
    }
    false
}

/// Locate the returned-closure body and its request-context parameter
/// name.  Gitea factories return `func(ctx *context.Context) { … }`; if
/// the function is itself the handler (`func req(ctx *Context){ … }`),
/// its own body/param are used.
fn guard_closure_and_ctx<'tree>(
    func_decl: Node<'tree>,
    bytes: &[u8],
) -> (Option<Node<'tree>>, String) {
    // Prefer the first returned `func_literal` (the middleware closure).
    if let Some(body) = func_decl.child_by_field_name("body") {
        let mut stack = vec![body];
        while let Some(n) = stack.pop() {
            if n.kind() == "func_literal" {
                let ctx = context_param_name(n, bytes).unwrap_or_else(|| "ctx".to_string());
                return (n.child_by_field_name("body"), ctx);
            }
            for child in named_children(n) {
                stack.push(child);
            }
        }
        // No inner closure: the function itself is the handler.
        let ctx = context_param_name(func_decl, bytes).unwrap_or_else(|| "ctx".to_string());
        return (Some(body), ctx);
    }
    (None, "ctx".to_string())
}

/// First parameter whose type text references a request `Context`
/// (`*context.Context`, `*context.APIContext`, …); falls back to the
/// first parameter name.
fn context_param_name(func_like: Node<'_>, bytes: &[u8]) -> Option<String> {
    let params = func_like.child_by_field_name("parameters")?;
    let mut first_name: Option<String> = None;
    for decl in named_children(params) {
        if decl.kind() != "parameter_declaration" {
            continue;
        }
        let name = decl
            .child_by_field_name("name")
            .map(|n| text(n, bytes))
            .or_else(|| {
                named_children(decl)
                    .into_iter()
                    .find(|c| c.kind() == "identifier")
                    .map(|c| text(c, bytes))
            });
        let type_text = decl
            .child_by_field_name("type")
            .map(|t| text(t, bytes))
            .unwrap_or_default();
        if type_text.contains("Context") {
            return name;
        }
        if first_name.is_none() {
            first_name = name;
        }
    }
    first_name
}

/// Leftmost identifier of a selector chain: `ctx.Repo.Permission.CanRead`
/// → `ctx`.
fn selector_root_ident(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(text(node, bytes)),
        "selector_expression" => node
            .child_by_field_name("operand")
            .and_then(|o| selector_root_ident(o, bytes)),
        "call_expression" => node
            .child_by_field_name("function")
            .and_then(|f| selector_root_ident(f, bytes)),
        "index_expression" | "parenthesized_expression" => node
            .child_by_field_name("operand")
            .or_else(|| named_children(node).into_iter().next())
            .and_then(|o| selector_root_ident(o, bytes)),
        _ => None,
    }
}

/// Find a top-level `func <name>(…)` declaration in the file.
fn find_top_level_go_func<'tree>(
    root: Node<'tree>,
    name: &str,
    bytes: &[u8],
) -> Option<Node<'tree>> {
    named_children(root).into_iter().find(|child| {
        child.kind() == "function_declaration"
            && child
                .child_by_field_name("name")
                .map(|n| text(n, bytes))
                .as_deref()
                == Some(name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_analysis::config::build_auth_rules;
    use crate::auth_analysis::extract::common::collect_top_level_units;
    use crate::auth_analysis::model::AuthCheckKind;
    use crate::utils::config::Config;
    use std::path::Path;
    use tree_sitter::Parser;

    fn parse_go(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_go::LANGUAGE))
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    fn run(src: &str) -> AuthorizationModel {
        let tree = parse_go(src);
        let bytes = src.as_bytes();
        let rules = build_auth_rules(&Config::default(), "go");
        let mut model = AuthorizationModel {
            lang: "go".into(),
            ..Default::default()
        };
        collect_top_level_units(tree.root_node(), bytes, &rules, &mut model);
        GiteaExtractor.extract(&tree, bytes, Path::new("api.go"), &rules, &mut model);
        model
    }

    const OWNERSHIP_GUARD_SRC: &str = r#"package packages
func reqRepoReader(unitType unit.Type) func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if !ctx.Repo.Permission.CanRead(unitType) && !ctx.IsUserRepoAdmin() && !ctx.IsUserSiteAdmin() {
			ctx.APIError(403, "no read permission")
			return
		}
	}
}
func Routes() {
	r.Group("/{username}", func() {
		r.Group("/packages", func() {
			r.Get("/{id}", GetPackage)
		}, reqRepoReader(unit.TypePackages))
	})
}
func GetPackage(ctx *context.APIContext) {
	id := ctx.PathParam("id")
	pkg, _ := packages_model.GetPackageByID(ctx, id)
	_ = pkg
}
"#;

    const FEATURE_GATE_SRC: &str = r#"package packages
func reqStarsEnabled() func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if setting.Repository.DisableStars {
			ctx.APIError(403, "stars disabled")
			return
		}
	}
}
func Routes() {
	r.Group("/{username}", func() {
		r.Group("/packages", func() {
			r.Get("/{id}", GetPackage)
		}, reqStarsEnabled())
	})
}
func GetPackage(ctx *context.APIContext) {
	id := ctx.PathParam("id")
	pkg, _ := packages_model.GetPackageByID(ctx, id)
	_ = pkg
}
"#;

    #[test]
    fn closure_group_ownership_guard_lifts_route_level_ownership_check() {
        let model = run(OWNERSHIP_GUARD_SRC);
        let has_lifted = model.units.iter().any(|u| {
            u.auth_checks.iter().any(|c| {
                c.kind == AuthCheckKind::Ownership
                    && c.is_route_level
                    && c.callee == "reqRepoReader"
            })
        });
        assert!(
            has_lifted,
            "ownership-guard middleware must be lifted onto the closure-nested handler as a \
             route-level Ownership check"
        );
    }

    #[test]
    fn feature_gate_middleware_not_recognised_as_auth() {
        let model = run(FEATURE_GATE_SRC);
        let recognised = model
            .units
            .iter()
            .any(|u| u.auth_checks.iter().any(|c| c.callee == "reqStarsEnabled"));
        assert!(
            !recognised,
            "feature-gate middleware (reads setting.* not ctx.* permission) must NOT be \
             recognised as an authorization check"
        );
    }

    #[test]
    fn middleware_is_ownership_guard_discriminates_authority_from_feature_gate() {
        let owner = parse_go(OWNERSHIP_GUARD_SRC);
        assert!(
            middleware_is_ownership_guard(
                owner.root_node(),
                "reqRepoReader",
                OWNERSHIP_GUARD_SRC.as_bytes()
            ),
            "reqRepoReader closure reads ctx.Repo.Permission.CanRead + emits ctx.APIError"
        );

        let gate = parse_go(FEATURE_GATE_SRC);
        assert!(
            !middleware_is_ownership_guard(
                gate.root_node(),
                "reqStarsEnabled",
                FEATURE_GATE_SRC.as_bytes()
            ),
            "reqStarsEnabled reads setting.* (global config), not a ctx.* permission field"
        );
    }

    #[test]
    fn parse_closure_group_extracts_prefix_and_trailing_middleware() {
        let src = r#"package p
func Routes() {
	r.Group("/api", func() {
		r.Get("/x", H)
	}, reqAdmin(), reqToken())
}
"#;
        let tree = parse_go(src);
        let bytes = src.as_bytes();
        // Find the outer Group call via a manual recursive walk.
        fn find_group<'t>(n: Node<'t>, bytes: &[u8]) -> Option<Node<'t>> {
            if n.kind() == "call_expression"
                && let Some(f) = n.child_by_field_name("function")
                && let Some((_, m)) = member_target(f, bytes)
                && m == "Group"
            {
                return Some(n);
            }
            for c in named_children(n) {
                if let Some(found) = find_group(c, bytes) {
                    return Some(found);
                }
            }
            None
        }
        let group_call = find_group(tree.root_node(), bytes).unwrap();
        let parsed = parse_closure_group(group_call, bytes).unwrap();
        assert_eq!(parsed.path_prefix, "/api");
        assert_eq!(parsed.middleware.len(), 2);
        assert_eq!(parsed.middleware[0].name, "reqAdmin");
        assert_eq!(parsed.middleware[1].name, "reqToken");
    }

    #[test]
    fn bare_closure_group_without_middleware_preserves_recall() {
        // A closure group with no trailing middleware must not synthesise
        // any auth — the handler stays unauthorized.
        let src = r#"package p
func Routes() {
	r.Group("/{username}", func() {
		r.Get("/{id}", GetPackage)
	})
}
func GetPackage(ctx *context.APIContext) {
	id := ctx.PathParam("id")
	pkg, _ := packages_model.GetPackageByID(ctx, id)
	_ = pkg
}
"#;
        let model = run(src);
        let any_route_level = model
            .units
            .iter()
            .any(|u| u.auth_checks.iter().any(|c| c.is_route_level));
        assert!(
            !any_route_level,
            "a group with no middleware must not manufacture route-level auth"
        );
    }

    #[test]
    fn group_prefilter_is_output_neutral() {
        // The `Group` byte pre-filter (perfhunt session-0051) must never drop a
        // real edge: on a gitea closure-group file it yields exactly the edges
        // the unconditional `harvest_edges` walk would, and on a Go file with no
        // `Group` token the walk produces nothing anyway, so skipping it is
        // sound.
        fn direct_walk(src: &str) -> Vec<CallerScopeEdge> {
            let tree = parse_go(src);
            let root = tree.root_node();
            let mut edges = Vec::new();
            harvest_edges(
                root,
                root,
                false,
                false,
                src.as_bytes(),
                Lang::Go,
                &mut edges,
            );
            edges
        }
        fn gated(src: &str) -> Vec<CallerScopeEdge> {
            let tree = parse_go(src);
            extract_route_handler_auth_edges(&tree, src.as_bytes(), Lang::Go)
        }

        // (a) gitea closure group (`Group` present) → gate does NOT skip; the
        //     harvested edge set is identical to the unconditional walk.
        let g = gated(OWNERSHIP_GUARD_SRC);
        let d = direct_walk(OWNERSHIP_GUARD_SRC);
        assert!(!g.is_empty(), "expected a harvested route→handler edge");
        assert_eq!(g.len(), d.len(), "prefilter dropped a gitea edge");
        assert_eq!(
            g[0].callee_leaf, d[0].callee_leaf,
            "prefilter changed the harvested edge"
        );
        assert_eq!(g[0].caller_authorized, d[0].caller_authorized);

        // (b) verb routes with no `Group` closure → prefilter skips, and the
        //     unconditional walk also yields nothing (skip is output-neutral).
        let no_group =
            "package p\nfunc Routes() {\n\tr.Get(\"/x\", GetX)\n\tr.Post(\"/y\", PostY)\n}\n";
        assert!(
            !no_group
                .as_bytes()
                .windows(b"Group".len())
                .any(|w| w == b"Group"),
            "fixture must not contain the Group token"
        );
        assert!(gated(no_group).is_empty(), "prefilter path must be empty");
        assert!(
            direct_walk(no_group).is_empty(),
            "a no-Group file must yield no edges even unconditionally"
        );
    }
}
