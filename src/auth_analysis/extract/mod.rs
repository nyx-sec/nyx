use super::config::AuthAnalysisRules;
use super::model::AuthorizationModel;
use crate::utils::project::{FrameworkContext, rust_file_imports_web_framework};
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
pub mod koa;
pub mod rails;
pub mod rocket;
pub mod sinatra;
pub mod spring;

pub trait AuthExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool;
    fn extract(
        &self,
        tree: &Tree,
        bytes: &[u8],
        path: &Path,
        rules: &AuthAnalysisRules,
    ) -> AuthorizationModel;
}

pub fn extract_authorization_model(
    lang: &str,
    framework_ctx: Option<&FrameworkContext>,
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
) -> AuthorizationModel {
    let extractors: [&dyn AuthExtractor; 13] = [
        &express::ExpressExtractor,
        &koa::KoaExtractor,
        &fastify::FastifyExtractor,
        &gin::GinExtractor,
        &echo::EchoExtractor,
        &flask::FlaskExtractor,
        &django::DjangoExtractor,
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

    for extractor in extractors {
        if extractor.supports(lang, framework_ctx) {
            let mut other = extractor.extract(tree, bytes, path, rules);
            // Preserve the canonical `lang` set above; sub-extractors
            // build their own default-initialised models with empty lang.
            other.lang = model.lang.clone();
            model.extend(other);
        }
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

    model
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
    for old_idx in 0..model.units.len() {
        let span = model.units[old_idx].span;
        let winner = *winner_by_span.get(&span).unwrap_or(&old_idx);
        if winner == old_idx {
            new_idx_for_old.insert(old_idx, surviving.len());
            surviving.push(model.units[old_idx].clone());
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
