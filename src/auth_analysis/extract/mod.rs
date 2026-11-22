use super::config::AuthAnalysisRules;
use super::model::{AuthCheck, AuthCheckKind, AuthorizationModel, CallSite, Framework};
use crate::utils::project::{FrameworkContext, rust_file_imports_web_framework};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::Tree;

pub mod actix_web;
pub mod axum;
pub mod common;
pub mod django;
pub mod echo;
pub mod express;
pub mod fastify;
pub mod flask;
pub mod gin;
pub mod gitea;
mod go_scope;
pub mod graphene;
mod js_scope;
pub mod koa;
mod py_models;
pub mod rails;
pub mod rocket;
pub mod sinatra;
pub mod spring;

pub trait AuthExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool;

    /// Returns true when this extractor expects the orchestrator to
    /// have already populated `model.units` with one
    /// `AnalysisUnitKind::Function` entry per top-level function /
    /// method via [`common::collect_top_level_units`].  Defaults to
    /// `true`; framework extractors that build their own unit set
    /// (Spring, Rails) override to `false` so the orchestrator skips
    /// the shared collection pass when only those extractors match.
    fn requires_top_level_units(&self) -> bool {
        true
    }

    fn extract(
        &self,
        tree: &Tree,
        bytes: &[u8],
        path: &Path,
        rules: &AuthAnalysisRules,
        model: &mut AuthorizationModel,
    );
}

pub fn extract_authorization_model(
    lang: &str,
    framework_ctx: Option<&FrameworkContext>,
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    cross_file_router_deps: Option<&HashMap<String, Vec<(CallSite, bool)>>>,
) -> AuthorizationModel {
    let extractors: [&dyn AuthExtractor; 15] = [
        &express::ExpressExtractor,
        &koa::KoaExtractor,
        &fastify::FastifyExtractor,
        &gin::GinExtractor,
        &gitea::GiteaExtractor,
        &echo::EchoExtractor,
        &flask::FlaskExtractor,
        &django::DjangoExtractor,
        &graphene::GrapheneExtractor,
        &spring::SpringExtractor,
        &rails::RailsExtractor,
        &sinatra::SinatraExtractor,
        &axum::AxumExtractor,
        &actix_web::ActixWebExtractor,
        &rocket::RocketExtractor,
    ];
    let mut model = AuthorizationModel {
        lang: lang.to_string(),
        ..Default::default()
    };
    // Pre-populate the cross-file router-dep map BEFORE extractors run.
    // FlaskExtractor reads `model.cross_file_router_deps` and merges the
    // resolved deps into its local router-deps map at extraction time,
    // so per-route auth attribution sees both the local-file
    // `dependencies=[Security(...)]` declarations and the cross-file
    // lift from `<parent>.include_router(<this_file>.<router>, ...)`
    // edges visible elsewhere in the project.  Empty / `None` for every
    // non-Python language and for files with no matching child edges.
    if let Some(deps) = cross_file_router_deps {
        model.cross_file_router_deps = deps.clone();
    }

    // **Hoist `collect_top_level_units` out of the per-extractor loop.**
    // For multi-extractor languages (Go: gin+echo, JS/TS: express+koa+
    // fastify, Python: flask+django, Rust: axum+actix_web+rocket, Ruby:
    // sinatra) the legacy code re-walked the entire AST and rebuilt the
    // `Function`-kind unit set per extractor (then deduped by span).
    // `collect_top_level_units` was the dominant cost in
    // `extract_authorization_model` (46% of total wall-clock on the
    // mattermost/server/channels/app subtree, 2026-05-04 profile).
    //
    // After the hoist each extractor receives a `&mut model` that
    // already carries the shared unit set; framework-specific work
    // (route detection, middleware injection, typed-extractor guards)
    // augments and promotes those units in place via the existing
    // `attach_route_handler` "promote-or-create" path.
    //
    // Spring + Rails build their own unit set (`maybe_collect_controller`
    // / Rails' `collect_nodes`), so they opt out via
    // `requires_top_level_units = false`; the shared pass runs only
    // when at least one matching extractor needs it.
    let any_requires_units = extractors
        .iter()
        .any(|e| e.supports(lang, framework_ctx) && e.requires_top_level_units());
    if any_requires_units {
        common::collect_top_level_units(tree.root_node(), bytes, rules, &mut model);
    }

    for extractor in extractors {
        if extractor.supports(lang, framework_ctx) {
            extractor.extract(tree, bytes, path, rules, &mut model);
        }
    }
    if lang == "python" {
        django::apply_view_decorator_checks(tree.root_node(), bytes, rules, &mut model);
    }

    // Per-language web-framework signal used to gate the param-name arm
    // of `unit_has_user_input_evidence`.  Combines the project-root
    // manifest detection (`framework_ctx`) with a per-file `use`/`import`
    // check, so a single file in a workspace whose root manifest does
    // not name a web framework can still opt back in by directly
    // importing one (e.g. `crates/collab/src/rpc.rs` in zed: workspace
    // root has no axum, but the file uses `axum::Router`).
    //
    // Three-valued: `Some(true)` keeps step 3 firing, `Some(false)`
    // suppresses it, `None` means no detection ran ─ behavior unchanged.
    model.lang_web_framework_signal = compute_web_framework_signal(lang, framework_ctx, bytes);
    // Schema migrations run from a management command, never from a
    // request, so they have no HTTP boundary whatever the project uses.
    if is_migration_path(lang, path) {
        model.lang_web_framework_signal = Some(false);
    }

    inject_route_level_middleware(&mut model, rules);

    // **Dedup units by span across extractors.**  Multiple extractors
    // (e.g. Flask + Django on a Python file) each call
    // `collect_top_level_units`, producing one unit per top-level
    // function.  When one extractor also recognises a route on that
    // function and promotes its copy to `RouteHandler` (with injected
    // middleware auth checks), the *other* extractor's untouched
    // `Function` copy still runs through `check_ownership_gaps` and
    // emits the FP from a unit that never saw the middleware-derived
    // auth check.
    //
    // This step keeps a single canonical unit per source span,
    // preferring `RouteHandler` over `Function`, merging auth_checks
    // and folding operation lists conservatively.  Route registrations
    // are remapped to the surviving unit index.
    deduplicate_units_by_span(&mut model);
    if lang == "python" {
        mark_internal_python_helpers(&mut model);
    }

    model
}

/// Set `AnalysisUnit::internal_helper` on module-private Python functions that
/// other functions of the file call, when no route handler reaches them
/// through those calls (directly or through further callers).
fn mark_internal_python_helpers(model: &mut AuthorizationModel) {
    use crate::auth_analysis::model::AnalysisUnitKind;
    use std::collections::HashSet;

    let leaf = |name: &str| name.rsplit(['.', ':']).next().unwrap_or(name).to_string();
    let mut callers_of: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, unit) in model.units.iter().enumerate() {
        let mut seen: HashSet<String> = HashSet::new();
        for call in &unit.call_sites {
            let callee = leaf(&call.name);
            if seen.insert(callee.clone()) {
                callers_of.entry(callee).or_default().push(idx);
            }
        }
    }
    let mut marks = Vec::new();
    for (idx, unit) in model.units.iter().enumerate() {
        let Some(name) = unit.name.as_deref() else {
            continue;
        };
        if !name.starts_with('_')
            || name.starts_with("__")
            || unit.kind == AnalysisUnitKind::RouteHandler
        {
            continue;
        }
        let Some(direct) = callers_of.get(name) else {
            continue;
        };
        let mut visited: HashSet<usize> = HashSet::from([idx]);
        let mut stack: Vec<usize> = direct.iter().copied().filter(|c| *c != idx).collect();
        let mut has_caller = !stack.is_empty();
        let mut route_reaches = false;
        while let Some(caller) = stack.pop() {
            if !visited.insert(caller) {
                continue;
            }
            let caller_unit = &model.units[caller];
            // A function view wired in a separate `urls.py` is not a
            // `RouteHandler` unit, but its `request` parameter marks it as
            // a web entry.
            if caller_unit.kind == AnalysisUnitKind::RouteHandler
                || caller_unit.params.iter().any(|p| is_request_param(p))
            {
                route_reaches = true;
                break;
            }
            if let Some(next) = caller_unit.name.as_deref().and_then(|n| callers_of.get(n)) {
                stack.extend(next.iter().copied().filter(|c| !visited.contains(c)));
            }
            has_caller = true;
        }
        if has_caller && !route_reaches {
            marks.push(idx);
        }
    }
    for idx in marks {
        model.units[idx].internal_helper = true;
    }
}

/// A Python parameter that names the incoming web request.
fn is_request_param(param: &str) -> bool {
    let name = param.split([':', '=']).next().unwrap_or(param).trim();
    matches!(name, "request" | "req" | "_request")
}

/// Django/Alembic (`migrations/`, `alembic/versions/`) and Rails
/// (`db/migrate/`) migration modules.  Only the file's own directory and its
/// parent are inspected, so an unrelated ancestor of the scan root named
/// `migrations` never matches.
fn is_migration_path(lang: &str, path: &Path) -> bool {
    if !matches!(lang, "python" | "ruby") {
        return false;
    }
    let name_of = |p: Option<&Path>| {
        p.and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string()
    };
    let dir = path.parent();
    let parent = name_of(dir);
    let grand = name_of(dir.and_then(|d| d.parent()));
    match parent.as_str() {
        "migrations" | "alembic" => true,
        "versions" => matches!(grand.as_str(), "migrations" | "alembic"),
        "migrate" => grand == "db",
        _ => false,
    }
}

/// Copy the authorization-bearing middleware of Express, Koa, Fastify, Gin,
/// Echo, axum and actix-web routes onto the handler unit as route-level
/// checks, the way the Flask, Django, Spring and Rails extractors already do
/// for decorators and filters.  `router.get('/docs/:id', checkOwnership,
/// handler)` authorizes the whole handler, but the call is opaque to the
/// per-subject coverage walk.
///
/// A handler registered on several routes keeps only the checks every
/// registration carries: one bare registration leaves it reachable without
/// the check.  Login-only middleware is left out because it never suppresses
/// an ownership finding.
fn inject_route_level_middleware(model: &mut AuthorizationModel, rules: &AuthAnalysisRules) {
    use std::collections::{BTreeMap, BTreeSet};

    // Registrations are grouped by the handler's source span, not its unit
    // index: every `attach_route_handler` call after the first builds a fresh
    // unit for the same function, and those copies are merged later.
    #[derive(Default)]
    struct Handler {
        units: BTreeSet<usize>,
        registrations: Vec<Vec<AuthCheck>>,
    }
    let mut per_handler: BTreeMap<(usize, usize), Handler> = BTreeMap::new();
    for route in &model.routes {
        if !matches!(
            route.framework,
            Framework::Express
                | Framework::Koa
                | Framework::Fastify
                | Framework::Gin
                | Framework::Echo
                | Framework::Axum
                | Framework::ActixWeb
        ) {
            continue;
        }
        let Some(unit) = model.units.get(route.unit_idx) else {
            continue;
        };
        let checks: Vec<AuthCheck> = route
            .middleware_calls
            .iter()
            .filter_map(|call| common::auth_check_from_call_site(call, route.line, rules))
            .filter(|check| {
                !matches!(
                    check.kind,
                    AuthCheckKind::LoginGuard
                        | AuthCheckKind::TokenExpiry
                        | AuthCheckKind::TokenRecipient
                )
            })
            .collect();
        let handler = per_handler.entry(unit.span).or_default();
        handler.units.insert(route.unit_idx);
        handler.registrations.push(checks);
    }

    for handler in per_handler.into_values() {
        let Some(first) = handler.registrations.first() else {
            continue;
        };
        let shared: Vec<AuthCheck> = first
            .iter()
            .filter(|check| {
                handler
                    .registrations
                    .iter()
                    .all(|reg| reg.iter().any(|other| other.callee == check.callee))
            })
            .cloned()
            .collect();
        for unit_idx in handler.units {
            let Some(unit) = model.units.get_mut(unit_idx) else {
                continue;
            };
            for check in &shared {
                let mut check = check.clone();
                check.is_route_level = true;
                let already = unit
                    .auth_checks
                    .iter()
                    .any(|existing| existing.callee == check.callee && existing.span == check.span);
                if !already {
                    unit.auth_checks.push(check);
                }
            }
        }
    }
}

/// Compute the per-file web-framework signal used to gate the
/// param-name arm of `unit_has_user_input_evidence`.
///
/// Currently emits a non-`None` value only for Rust files.  The Rust
/// auth analysis is the single biggest source of internal-helper FPs
/// in non-web crates (zed's GUI / editor crates); the other languages
/// have their own handler-classification policies that already filter
/// effectively, so they keep their existing behavior (None →
/// fall-through to the param-name heuristic) until each is validated.
///
/// Three-valued semantics:
/// * `Some(true)` ─ project root manifest names a Rust web framework
///   (axum / actix_web / rocket), OR the file directly imports one.
///   Param-name evidence stays on.
/// * `Some(false)` ─ project root manifest was inspected (Cargo.toml
///   exists) and named no Rust web framework, AND the file does not
///   directly import one.  Param-name evidence is suppressed: the
///   project has no HTTP boundary in Rust.
/// * `None` ─ no detection ran (no `framework_ctx`, no Cargo.toml
///   inspected).  Behavior unchanged.
fn compute_web_framework_signal(
    lang: &str,
    framework_ctx: Option<&FrameworkContext>,
    bytes: &[u8],
) -> Option<bool> {
    if !matches!(lang, "rust" | "rs") {
        return None;
    }
    let project_signal = framework_ctx.and_then(|ctx| ctx.lang_has_web_framework("rust"));
    if project_signal == Some(true) {
        return Some(true);
    }
    // Project says "no Rust framework" or never inspected.  Consult the
    // file's own imports as a per-file fallback; if the file uses an
    // axum / actix_web / rocket symbol directly, treat it as a handler
    // file even when the workspace-root Cargo.toml does not list the
    // crate.  (Real example: zed's `crates/collab/src/rpc.rs` imports
    // axum but the workspace root Cargo.toml does not.)
    if rust_file_imports_web_framework(bytes) {
        return Some(true);
    }
    // No file-level evidence either.  Only flip to `Some(false)` if a
    // Cargo.toml manifest was actually inspected — single-file scans
    // without project context get `None` and preserve prior behavior.
    project_signal
}

fn deduplicate_units_by_span(model: &mut AuthorizationModel) {
    use crate::auth_analysis::model::{AnalysisUnit, AnalysisUnitKind};
    use std::collections::HashMap;

    // First pass: choose a winner for each span, prefer the
    // first-seen `RouteHandler` over any `Function` copy.
    let mut winner_by_span: HashMap<(usize, usize), usize> = HashMap::new();
    for (idx, unit) in model.units.iter().enumerate() {
        let key = unit.span;
        match winner_by_span.get(&key) {
            None => {
                winner_by_span.insert(key, idx);
            }
            Some(&existing) => {
                let prev_kind = model.units[existing].kind;
                if prev_kind != AnalysisUnitKind::RouteHandler
                    && unit.kind == AnalysisUnitKind::RouteHandler
                {
                    winner_by_span.insert(key, idx);
                }
            }
        }
    }

    // Second pass: drain auth_checks from losers so we can append them
    // to the winners after the layout collapses.
    let mut moved_checks: Vec<Vec<crate::auth_analysis::model::AuthCheck>> =
        Vec::with_capacity(model.units.len());
    for old_idx in 0..model.units.len() {
        let span = model.units[old_idx].span;
        let winner = *winner_by_span.get(&span).unwrap_or(&old_idx);
        if winner == old_idx {
            moved_checks.push(Vec::new());
        } else {
            moved_checks.push(std::mem::take(&mut model.units[old_idx].auth_checks));
        }
    }

    // Third pass: emit surviving units (clone the winners) and build
    // the old-idx → new-idx remap.
    let mut new_idx_for_old: HashMap<usize, usize> = HashMap::new();
    let mut surviving: Vec<AnalysisUnit> = Vec::with_capacity(winner_by_span.len());
    for (old_idx, unit) in model.units.iter().enumerate() {
        let winner = *winner_by_span.get(&unit.span).unwrap_or(&old_idx);
        if winner == old_idx {
            new_idx_for_old.insert(old_idx, surviving.len());
            surviving.push(unit.clone());
        }
    }

    // Fourth pass: drain loser auth_checks into their winners, deduping
    // by (span, callee).  Operations are not merged: both extractor
    // passes recompute the same operation list from the AST, so the
    // winner already carries the canonical set.
    for (old_idx, checks) in moved_checks.iter_mut().enumerate() {
        let span = model.units[old_idx].span;
        let winner = *winner_by_span.get(&span).unwrap_or(&old_idx);
        if winner == old_idx {
            continue;
        }
        let Some(&new_winner_idx) = new_idx_for_old.get(&winner) else {
            continue;
        };
        for check in checks.drain(..) {
            let already_present = surviving[new_winner_idx]
                .auth_checks
                .iter()
                .any(|existing| existing.span == check.span && existing.callee == check.callee);
            if !already_present {
                surviving[new_winner_idx].auth_checks.push(check);
            }
        }
    }

    model.units = surviving;
    for route in &mut model.routes {
        if let Some(&new_idx) = new_idx_for_old.get(&route.unit_idx) {
            route.unit_idx = new_idx;
        }
    }
}
