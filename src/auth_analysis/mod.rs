//! Missing authorization and ownership checks (Rust-primary).
//!
//! Detects request handlers that reach a privileged operation taking a scoped
//! identifier (`*_id`, row reference, scoped resource) without a preceding
//! ownership or membership check.
//!
//! Other languages have rule scaffolding (`py.auth.*`, `js.auth.*`,
//! `rb.auth.*`, `go.auth.*`, `java.auth.*`) but only Rust has benchmark
//! corpus coverage and validated precision. Treat non-Rust findings as preview.
//!
//! # Rule IDs
//!
//! | Rule ID | Variant |
//! |---------|---------|
//! | `rs.auth.missing_ownership_check` | Standalone structural analyser (default on) |
//! | `rs.auth.missing_ownership_check.taint` | SSA/taint variant via `Cap::UNAUTHORIZED_ID` (default off) |
//!
//! Enable the taint variant via `scanner.enable_auth_as_taint = true` in
//! `nyx.conf`. Run both together when enabled; if both fire for the same site,
//! treat them as the same finding.
//!
//! # What counts as authorization
//!
//! The analyser accepts any of:
//! - A call to a recognised authorization helper (`check_ownership`,
//!   `has_permission`, `require_*_member`, etc.; configurable per project).
//! - An ownership-equality check on a row reference
//!   (`if owner_id != user.id { return 403 }`).
//! - A self-actor reference from a typed extractor param (`Extension<Session>`,
//!   `CurrentUser`, etc.) combined with `user.id` / `user.user_id` use.
//! - A typed policy-guard wrapper (`GuardedData<ActionPolicy<X>, _>`);
//!   configured via `policy_guard_names`.
//! - A SQL query joining through an ACL table or filtering by `user_id`
//!   predicate (detected without a SQL parser via [`sql_semantics`]).
//! - A helper-summary lift: a called function whose body contains a
//!   `require_*_member` call (fixed-point up to 4 iterations).
//!
//! # Sink classification
//!
//! | Class | Examples | Treatment |
//! |-------|---------|-----------|
//! | `InMemoryLocal` | `map.insert`, `vec.push` on local | Never a sink |
//! | `RealtimePublish` | `realtime.publish_to_group` | Sink unless channel scope is ownership-checked |
//! | `OutboundNetwork` | `http.post`, `reqwest::Client::post` | Sink unless sanitizer is on the path |
//! | `CacheCrossTenant` | `redis.set` with scoped keys | Sink unless tenant is checked |
//! | `DbMutation` | `db.insert`, `repo.save` with scoped IDs | Sink unless ownership is established |
//! | `DbCrossTenantRead` | `db.query` returning tenant-scoped rows | Sink unless ACL-join or tenant predicate is present |
//!
//! # Submodules
//!
//! - [`checks`]: ownership-check recognition, actor-context extraction,
//!   row-field variable tracking
//! - [`config`]: per-language auth rule defaults and config merging
//! - [`extract`]: handler detection, scoped-ID extraction, summary lifting
//! - [`model`]: `AnalysisUnit`, `AuthCheck`, `SensitiveOperation`, `SinkClass`
//! - [`sql_semantics`]: ACL-join and `user_id`-predicate detection without a
//!   SQL parser

pub mod checks;
pub mod config;
pub mod extract;
pub mod model;
pub mod router_facts;
pub mod sql_semantics;

use crate::commands::scan::Diag;
use crate::evidence::{Confidence, Evidence, SpanEvidence};
use crate::patterns::FindingCategory;
use crate::ssa::type_facts::TypeKind;
use crate::summary::GlobalSummaries;
use crate::symbol::{FuncKey, Lang, normalize_namespace};
use crate::utils::Config;
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::Tree;

fn byte_offset_to_point(tree: &Tree, byte: usize) -> tree_sitter::Point {
    tree.root_node()
        .descendant_for_byte_range(byte, byte)
        .map(|node| node.start_position())
        .unwrap_or(tree_sitter::Point { row: 0, column: 0 })
}

/// Per-file snapshot of SSA-derived variable types, keyed by
/// source-level variable name.  Built at `run_auth_analysis` call sites
/// by merging type facts across all bodies in the file; a variable name
/// with conflicting types in different bodies is dropped (absence is
/// safe, the sink gate just falls back to name-based classification).
pub type VarTypes = HashMap<String, TypeKind>;

#[allow(clippy::too_many_arguments)]
pub fn run_auth_analysis(
    tree: &Tree,
    source: &[u8],
    lang: &str,
    file_path: &Path,
    cfg: &Config,
    var_types: Option<&VarTypes>,
    global_summaries: Option<&GlobalSummaries>,
    scan_root: Option<&Path>,
) -> Vec<Diag> {
    let rules = config::build_auth_rules(cfg, lang);
    if !rules.enabled {
        return Vec::new();
    }
    // Resolve cross-file router-deps for the active file (Python only)
    // before constructing the model, so the FlaskExtractor sees the
    // full per-file dep map at extraction time.  See `router_facts`
    // module + `analyse_file_fused` for the wider pipeline.
    let cross_file_router_deps = resolve_cross_file_router_deps_for_file(
        lang,
        file_path,
        global_summaries,
    );
    let model = extract::extract_authorization_model(
        lang,
        cfg.framework_ctx.as_ref(),
        tree,
        source,
        file_path,
        &rules,
        cross_file_router_deps.as_ref(),
    );
    run_auth_analysis_with_model(
        model,
        tree,
        lang,
        file_path,
        &rules,
        var_types,
        global_summaries,
        scan_root,
    )
}

/// Look up `GlobalSummaries.router_facts_by_module` and resolve the
/// cross-file router-deps map for the file at `file_path`.  Returns
/// `None` for non-Python files, files whose module_id has no matching
/// `<parent>.include_router(<this_file>.<var>, ...)` edges anywhere in
/// the project, or callers that don't pass `global_summaries`.
pub(crate) fn resolve_cross_file_router_deps_for_file(
    lang: &str,
    file_path: &Path,
    global_summaries: Option<&GlobalSummaries>,
) -> Option<HashMap<String, Vec<(model::CallSite, bool)>>> {
    if lang != "python" {
        return None;
    }
    let gs = global_summaries?;
    let module_id = router_facts::module_id_for_path(file_path)?;
    let resolved = gs.resolve_cross_file_router_deps(&module_id);
    if resolved.is_empty() { None } else { Some(resolved) }
}

/// Variant of [`run_auth_analysis`] that accepts a pre-built
/// [`model::AuthorizationModel`] instead of building one from the AST.
///
/// Lets callers that need both diagnostics AND
/// `(FuncKey, AuthCheckSummary)` per-file summaries (the fused pass-2
/// path in [`crate::ast::analyse_file_fused`]) construct the base
/// authorization model exactly once and route both consumers through
/// it.  Pre-fix the fused path called
/// [`extract::extract_authorization_model`] twice per file (once via
/// [`run_auth_analysis`], once via [`extract_auth_summaries_by_key`]),
/// duplicating the AST walks for `collect_top_level_units` +
/// `build_function_unit_with_meta` + `collect_unit_state` + every
/// extractor's framework-detection scan.  On the
/// `mattermost/server/channels/app` profile that double-extract
/// accounted for 35.3% of total wall-clock; sharing the base model
/// drops it to ~17.6%.
///
/// The mutations applied here ([`apply_var_types_to_model`],
/// [`apply_typed_bounded_params`], [`apply_helper_lifting`]) only
/// affect diagnostic emission — `extract_auth_summaries_from_model`
/// reads the **base** model so callers must extract summaries before
/// passing the model in.
#[allow(clippy::too_many_arguments)]
pub fn run_auth_analysis_with_model(
    mut model: model::AuthorizationModel,
    tree: &Tree,
    lang: &str,
    file_path: &Path,
    rules: &config::AuthAnalysisRules,
    var_types: Option<&VarTypes>,
    global_summaries: Option<&GlobalSummaries>,
    scan_root: Option<&Path>,
) -> Vec<Diag> {
    if !rules.enabled {
        return Vec::new();
    }

    // Refine `SensitiveOperation::sink_class` using SSA-derived
    // variable types.  Runs only when the caller supplied `var_types`
    // (skipped for slug-lookup / unit-test call sites).
    if let Some(types) = var_types {
        apply_var_types_to_model(&mut model, rules, types);
        apply_typed_bounded_params(&mut model, types);
    }

    // Lift per-function auth-check summaries and synthesise call-site
    // `AuthCheck`s in callers, so a handler that delegates to a helper
    // which internally validates ownership is recognised as
    // auth-checked.  Iterated to a small fixpoint so transitive helper
    // chains are also covered; consults `global_summaries.auth_by_key`
    // (when provided) for cross-file helpers that live in other files.
    apply_helper_lifting(&mut model, lang, file_path, scan_root, global_summaries);

    if model.routes.is_empty() && model.units.is_empty() {
        return Vec::new();
    }

    checks::run_checks(&model, rules)
        .into_iter()
        .map(|finding| auth_finding_to_diag(&finding, tree, file_path))
        .collect()
}

/// Build per-function [`model::AuthCheckSummary`] entries for every
/// unit in `model`, keyed by a canonical [`FuncKey`] derived from the
/// enclosing file's path and the unit's leaf name + arity.
///
/// Used by pass 1 to persist per-file auth summaries for cross-file
/// helper lifting.  Only returns summaries for units whose body
/// already proves at least one positional parameter under ownership /
/// membership / admin / authorization check, i.e. the exact
/// single-file lift set, so the cross-file variant does not widen what
/// counts as a helper.
pub fn extract_auth_summaries_by_key(
    tree: &Tree,
    source: &[u8],
    lang: &str,
    file_path: &Path,
    cfg: &Config,
    scan_root: Option<&Path>,
) -> Vec<(FuncKey, model::AuthCheckSummary)> {
    let rules = config::build_auth_rules(cfg, lang);
    if !rules.enabled {
        return Vec::new();
    }
    let model = extract::extract_authorization_model(
        lang,
        cfg.framework_ctx.as_ref(),
        tree,
        source,
        file_path,
        &rules,
        None,
    );
    extract_auth_summaries_from_model(&model, lang, file_path, scan_root)
}

/// Variant of [`extract_auth_summaries_by_key`] that consumes a
/// pre-built [`model::AuthorizationModel`].
///
/// Designed for callers that also need to run the diagnostic pipeline
/// (which mutates the model via [`run_auth_analysis_with_model`]):
/// extract summaries first against the base model, then hand the same
/// model to the diag pipeline so the second
/// [`extract::extract_authorization_model`] AST walk per file is
/// avoided.  See [`run_auth_analysis_with_model`] for the wider
/// rationale and measured saving.
pub fn extract_auth_summaries_from_model(
    model: &model::AuthorizationModel,
    lang: &str,
    file_path: &Path,
    scan_root: Option<&Path>,
) -> Vec<(FuncKey, model::AuthCheckSummary)> {
    summaries_keyed_by_func(model, lang, file_path, scan_root)
}

/// Convert an already-built [`model::AuthorizationModel`] into a
/// canonical `(FuncKey, AuthCheckSummary)` list suitable for
/// persistence.  Shares the per-unit summary-building logic with
/// [`build_helper_summaries`] so single-file and cross-file lifts
/// accept the exact same set of helpers.
fn summaries_keyed_by_func(
    model: &model::AuthorizationModel,
    lang: &str,
    file_path: &Path,
    scan_root: Option<&Path>,
) -> Vec<(FuncKey, model::AuthCheckSummary)> {
    let Some(lang_enum) = Lang::from_slug(lang) else {
        return Vec::new();
    };
    let path_str = file_path.to_string_lossy();
    let root_str = scan_root.map(|r| r.to_string_lossy().into_owned());
    let namespace = normalize_namespace(&path_str, root_str.as_deref());

    let mut out = Vec::new();
    for unit in &model.units {
        let Some(name) = unit.name.as_deref() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Some(summary) = build_unit_summary(unit) else {
            continue;
        };
        let leaf = name.rsplit('.').next().unwrap_or(name).to_string();
        let key = FuncKey {
            lang: lang_enum,
            namespace: namespace.clone(),
            container: String::new(),
            name: leaf,
            arity: Some(unit.params.len()),
            disambig: None,
            kind: crate::symbol::FuncKind::Function,
        };
        out.push((key, summary));
    }
    out
}

/// Build an [`model::AuthCheckSummary`] for a single
/// [`model::AnalysisUnit`].  Returns `None` when the unit produces no
/// usable param → auth-kind mapping, so callers can cheaply skip
/// persisting empty entries.
fn build_unit_summary(unit: &model::AnalysisUnit) -> Option<model::AuthCheckSummary> {
    use model::{AuthCheckKind, AuthCheckSummary};
    if unit.params.is_empty() {
        return None;
    }
    let mut summary = AuthCheckSummary::default();
    for check in &unit.auth_checks {
        if matches!(
            check.kind,
            AuthCheckKind::LoginGuard | AuthCheckKind::TokenExpiry | AuthCheckKind::TokenRecipient
        ) {
            continue;
        }
        for subject in &check.subjects {
            let Some(candidate) = subject_lift_key(subject) else {
                continue;
            };
            if let Some(idx) = unit.params.iter().position(|p| p == &candidate) {
                summary
                    .param_auth_kinds
                    .entry(idx)
                    .and_modify(|existing| {
                        *existing = stronger_check_kind(*existing, check.kind);
                    })
                    .or_insert(check.kind);
            }
        }
    }
    if summary.param_auth_kinds.is_empty() {
        None
    } else {
        Some(summary)
    }
}

/// Walk every `SensitiveOperation` in the model and, when the call's
/// receiver root variable has a known SSA type, override `sink_class`
/// to the type-implied class.  Strictly additive, only overrides
/// when the type map produces a definite class, otherwise leaves the
/// name/prefix-derived classification intact.
fn apply_var_types_to_model(
    model: &mut model::AuthorizationModel,
    rules: &config::AuthAnalysisRules,
    var_types: &VarTypes,
) {
    for unit in &mut model.units {
        for op in &mut unit.operations {
            let Some(first) = receiver_root(&op.callee) else {
                continue;
            };
            let Some(ty) = var_types.get(first) else {
                continue;
            };
            if let Some(new_class) = sink_class_for_type(ty, &op.callee, rules) {
                op.sink_class = Some(new_class);
            }
        }
    }
}

/// Populate each [`model::AnalysisUnit::typed_bounded_vars`] with the
/// names of formal parameters whose SSA-inferred [`TypeKind`] is a
/// payload-incompatible scalar ([`TypeKind::Int`] or
/// [`TypeKind::Bool`]).  Only parameter-rooted entries are considered;
/// function-local bindings stay outside this set so a downstream
/// reassignment from user input (`let id = req.params.id`) never gets
/// suppressed by accident.
///
/// when a parameter's type is a [`TypeKind::Dto`], lift each
/// of its `Int`/`Bool` fields as `typed_bounded_dto_fields[<param>]`
/// so member-access subjects like `dto.age` are recognised as
/// payload-incompatible.  Only fires when the base param itself was
/// recognised as a typed extractor by a typed-extractor matcher, bare
/// parameters with no framework gate never lift their fields.
fn apply_typed_bounded_params(model: &mut model::AuthorizationModel, var_types: &VarTypes) {
    for unit in &mut model.units {
        for name in &unit.params {
            let Some(ty) = var_types.get(name) else {
                continue;
            };
            match ty {
                TypeKind::Int | TypeKind::Bool => {
                    unit.typed_bounded_vars.insert(name.clone());
                }
                TypeKind::Dto(dto) => {
                    let mut bounded = Vec::new();
                    for (field_name, field_kind) in &dto.fields {
                        if matches!(field_kind, TypeKind::Int | TypeKind::Bool) {
                            bounded.push(field_name.clone());
                        }
                    }
                    if !bounded.is_empty() {
                        unit.typed_bounded_dto_fields.insert(name.clone(), bounded);
                    }
                }
                _ => {}
            }
        }
    }
}

/// First segment of a callee's receiver chain (`map.insert` → `"map"`,
/// `self.cache.set` → `"self"`).  Returns `None` when the callee has no
/// receiver (e.g. a free function call).
fn receiver_root(callee: &str) -> Option<&str> {
    let (first, rest) = callee.split_once('.')?;
    if rest.is_empty() {
        return None;
    }
    if first.is_empty() { None } else { Some(first) }
}

/// Map an inferred [`TypeKind`] to the [`model::SinkClass`] that should
/// supersede the callee-name classification.  The DB case disambiguates
/// read vs mutation using the callee's verb; non-security types return
/// `None` so the caller leaves the existing class in place.
fn sink_class_for_type(
    ty: &TypeKind,
    callee: &str,
    rules: &config::AuthAnalysisRules,
) -> Option<model::SinkClass> {
    match ty {
        TypeKind::LocalCollection => Some(model::SinkClass::InMemoryLocal),
        TypeKind::HttpClient => Some(model::SinkClass::OutboundNetwork),
        TypeKind::DatabaseConnection => {
            if rules.is_read(callee) && !rules.is_mutation(callee) {
                Some(model::SinkClass::DbCrossTenantRead)
            } else {
                Some(model::SinkClass::DbMutation)
            }
        }
        _ => None,
    }
}

/// Build per-function `AuthCheckSummary` and synthesise `AuthCheck`s
/// at every call site that targets a known helper whose summary names
/// auth-checked params.  Iterated to a small fixpoint
/// so transitive helper chains (`handler → validate → require_member`)
/// are also covered.
///
/// The synthesised AuthCheck inherits the helper-param's check kind
/// and is anchored at the call site's line, with subjects = the
/// caller's value-refs from the corresponding positional argument.
/// `auth_check_covers_subject` then matches them against downstream
/// sensitive operations exactly like a real prior auth check.
///
/// When `global_summaries` is `Some`, cross-file helpers are looked up
/// via [`GlobalSummaries::get_auth`] after the same-file summary
/// gather, this recovers the handler-in-file-A calling
/// `require_owner`-in-file-B case that single-file lifting cannot see.
fn apply_helper_lifting(
    model: &mut model::AuthorizationModel,
    lang: &str,
    file_path: &Path,
    scan_root: Option<&Path>,
    global_summaries: Option<&GlobalSummaries>,
) {
    use std::collections::HashSet;

    let caller_lang = Lang::from_slug(lang);
    let path_str = file_path.to_string_lossy();
    let root_str = scan_root.map(|r| r.to_string_lossy().into_owned());
    let caller_namespace = normalize_namespace(&path_str, root_str.as_deref());

    const MAX_ROUNDS: usize = 4;
    for _ in 0..MAX_ROUNDS {
        let summaries = build_helper_summaries(model);
        let have_same_file = !summaries.is_empty();
        let have_cross_file =
            global_summaries.is_some_and(|gs| gs.auth_by_key().is_some()) && caller_lang.is_some();
        if !have_same_file && !have_cross_file {
            return;
        }
        let mut added = false;
        // For each unit, compute synthetic checks BEFORE mutating, so
        // a helper-call inside one unit doesn't see synthetic checks
        // we add to a sibling in the same round (those land in the
        // next iteration via the rebuilt summaries).
        let synth: Vec<(usize, Vec<model::AuthCheck>)> = model
            .units
            .iter()
            .enumerate()
            .map(|(idx, unit)| {
                let mut out = synthesise_checks_for_unit(unit, &summaries);
                if have_cross_file
                    && let (Some(gs), Some(lang_enum)) = (global_summaries, caller_lang)
                {
                    out.extend(synthesise_cross_file_checks_for_unit(
                        unit,
                        &summaries,
                        gs,
                        lang_enum,
                        &caller_namespace,
                    ));
                }
                (idx, out)
            })
            .collect();
        let mut existing_keys_per_unit: Vec<HashSet<((usize, usize), model::AuthCheckKind)>> =
            model
                .units
                .iter()
                .map(|u| {
                    u.auth_checks
                        .iter()
                        .map(|c| (c.span, c.kind))
                        .collect::<HashSet<_>>()
                })
                .collect();
        for (idx, checks) in synth {
            for check in checks {
                let key = (check.span, check.kind);
                if existing_keys_per_unit[idx].insert(key) {
                    model.units[idx].auth_checks.push(check);
                    added = true;
                }
            }
        }
        if !added {
            return;
        }
    }
}

/// Build a `name → AuthCheckSummary` map by walking each unit's auth
/// checks and recording, for every check subject whose value-ref name
/// matches a positional parameter name of the unit, that param index
/// → check kind.  Same key with different kinds collapses to the most
/// specific (Ownership/Membership wins over Other).
fn build_helper_summaries(
    model: &model::AuthorizationModel,
) -> std::collections::HashMap<String, model::AuthCheckSummary> {
    use model::{AuthCheckKind, AuthCheckSummary};
    use std::collections::HashMap;

    let mut summaries: HashMap<String, AuthCheckSummary> = HashMap::new();
    for unit in &model.units {
        let Some(name) = unit.name.as_deref() else {
            continue;
        };
        if name.is_empty() || unit.params.is_empty() {
            continue;
        }
        let mut summary = AuthCheckSummary::default();
        for check in &unit.auth_checks {
            // We only lift checks that actively prove ownership /
            // membership / admin-rights / authorize-helper, login
            // and token-validity checks don't justify foreign-id
            // mutations and we want to keep parity with
            // `has_prior_subject_auth`'s filter.
            if matches!(
                check.kind,
                AuthCheckKind::LoginGuard
                    | AuthCheckKind::TokenExpiry
                    | AuthCheckKind::TokenRecipient
            ) {
                continue;
            }
            for subject in &check.subjects {
                let candidate = subject_lift_key(subject);
                let Some(candidate) = candidate else { continue };
                if let Some(idx) = unit.params.iter().position(|p| p == &candidate) {
                    summary
                        .param_auth_kinds
                        .entry(idx)
                        .and_modify(|existing| {
                            *existing = stronger_check_kind(*existing, check.kind);
                        })
                        .or_insert(check.kind);
                }
            }
        }
        if !summary.param_auth_kinds.is_empty() {
            // Deduplicate by last segment of the function name, the
            // lifting site matches the call's last segment too.
            let last = name.rsplit('.').next().unwrap_or(name).to_string();
            summaries
                .entry(last)
                .or_default()
                .param_auth_kinds
                .extend(summary.param_auth_kinds);
        }
    }
    summaries
}

/// Pick the identifier name for a check subject for purposes of
/// matching to the enclosing function's parameters.  We prefer the
/// `base` segment of a member-chain subject (`row.user_id` → `row`)
/// because helpers usually receive the full struct, not the field;
/// fall back to the raw `name` for plain identifiers.
fn subject_lift_key(subject: &model::ValueRef) -> Option<String> {
    if let Some(base) = subject.base.as_deref() {
        let first = base.split('.').next().unwrap_or(base).trim();
        if !first.is_empty() {
            return Some(first.to_string());
        }
    }
    if subject.name.is_empty() {
        None
    } else {
        Some(
            subject
                .name
                .split('.')
                .next()
                .unwrap_or(&subject.name)
                .to_string(),
        )
    }
}

fn stronger_check_kind(a: model::AuthCheckKind, b: model::AuthCheckKind) -> model::AuthCheckKind {
    use model::AuthCheckKind::*;
    fn rank(k: model::AuthCheckKind) -> u8 {
        match k {
            Ownership => 5,
            Membership => 4,
            AdminGuard => 3,
            Other => 2,
            LoginGuard => 1,
            TokenExpiry | TokenRecipient => 0,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

/// For one unit, synthesise an `AuthCheck` at every call site that
/// targets a helper with a non-trivial summary.  Subjects are taken
/// from `call_site.args_value_refs[K]` for each auth-checked param
/// position K, these are the caller's concrete subjects passed at
/// that arg slot, exactly what `auth_check_covers_subject` needs.
fn synthesise_checks_for_unit(
    unit: &model::AnalysisUnit,
    summaries: &std::collections::HashMap<String, model::AuthCheckSummary>,
) -> Vec<model::AuthCheck> {
    let line_of = |span: (usize, usize)| -> usize {
        // Span is byte offsets; we don't have direct access to a Tree
        // here. Caller assigns line via `line` field on call_site
        // through CallSite metadata absence, fall back to the unit's
        // line since covers_subject uses `check.line <= op.line` and
        // helper calls are typically near the unit start.
        let _ = span;
        unit.line
    };

    let mut out = Vec::new();
    for call in &unit.call_sites {
        let last = call.name.rsplit('.').next().unwrap_or(&call.name);
        let Some(summary) = summaries.get(last) else {
            continue;
        };
        // A call to the unit itself shouldn't lift anything (would
        // produce a tautological self-cover).
        if unit.name.as_deref() == Some(last) {
            continue;
        }
        // Build subjects from the auth-checked param positions.
        let mut subjects: Vec<model::ValueRef> = Vec::new();
        let mut effective_kind = model::AuthCheckKind::Other;
        for (param_idx, kind) in &summary.param_auth_kinds {
            let Some(arg_refs) = call.args_value_refs.get(*param_idx) else {
                continue;
            };
            subjects.extend(arg_refs.iter().cloned());
            effective_kind = stronger_check_kind(effective_kind, *kind);
        }
        if subjects.is_empty() {
            continue;
        }
        let line = call_site_line(unit, call).unwrap_or_else(|| line_of(call.span));
        out.push(model::AuthCheck {
            kind: effective_kind,
            callee: format!("(lifted {})", call.name),
            subjects,
            span: call.span,
            line,
            args: call.args.clone(),
            condition_text: None,
            is_route_level: false,
        });
    }
    out
}

/// Approximate the call site's line.  We don't have tree access here,
/// so we walk the unit's existing operations / call_sites to find one
/// whose span starts at the same byte offset and reuse its line; if
/// nothing matches we conservatively report the unit's start line so
/// the synthetic check still satisfies `check.line <= op.line` for
/// operations declared after it.  In practice, helper calls always
/// resolve via the operations match because handlers register their
/// own call_site too.
fn call_site_line(unit: &model::AnalysisUnit, call: &model::CallSite) -> Option<usize> {
    for op in &unit.operations {
        if op.span.0 == call.span.0 {
            return Some(op.line);
        }
    }
    None
}

/// Cross-file variant of [`synthesise_checks_for_unit`], for each
/// call site in `unit`, resolve the callee against `GlobalSummaries`
/// and look up an `AuthCheckSummary` that was persisted by some other
/// file's pass-1 extraction.  Skips call sites already handled by the
/// single-file map (`same_file_summaries`) so we do not double-lift
/// the same call.
///
/// The synthesised check carries the same shape as the single-file
/// version: subjects come from `call.args_value_refs[K]` at each
/// auth-checked param position K, effective kind is the strongest
/// check kind across those positions, and the `(lifted cross-file
/// <name>)` callee string distinguishes cross-file lifts in
/// diagnostics.
fn synthesise_cross_file_checks_for_unit(
    unit: &model::AnalysisUnit,
    same_file_summaries: &std::collections::HashMap<String, model::AuthCheckSummary>,
    gs: &GlobalSummaries,
    caller_lang: Lang,
    caller_namespace: &str,
) -> Vec<model::AuthCheck> {
    let mut out = Vec::new();
    for call in &unit.call_sites {
        let last = call.name.rsplit('.').next().unwrap_or(&call.name);
        if unit.name.as_deref() == Some(last) {
            continue;
        }
        // Skip if the single-file map already handled this callee ,
        // that path has richer same-file context (existing
        // summaries from sibling units in this model) and its
        // synthesised check is strictly more precise.
        if same_file_summaries.contains_key(last) {
            continue;
        }

        let arity_hint = Some(call.args.len());
        let key = match gs.resolve_callee_key(last, caller_lang, caller_namespace, arity_hint) {
            crate::summary::CalleeResolution::Resolved(key) => key,
            _ => continue,
        };
        // Auth summaries are persisted with a canonical key:
        // `disambig=None`, `container=""`, `kind=Function`.  Normalise
        // the resolver's key to that canonical shape before looking up
        // so a byte-offset or DFS-index `disambig` on the resolved key
        // doesn't cause a trivial miss.
        let mut canonical = key.clone();
        canonical.disambig = None;
        canonical.container = String::new();
        canonical.kind = crate::symbol::FuncKind::Function;
        let Some(summary) = gs.get_auth(&canonical) else {
            continue;
        };

        let mut subjects: Vec<model::ValueRef> = Vec::new();
        let mut effective_kind = model::AuthCheckKind::Other;
        for (param_idx, kind) in &summary.param_auth_kinds {
            let Some(arg_refs) = call.args_value_refs.get(*param_idx) else {
                continue;
            };
            subjects.extend(arg_refs.iter().cloned());
            effective_kind = stronger_check_kind(effective_kind, *kind);
        }
        if subjects.is_empty() {
            continue;
        }
        let line = call_site_line(unit, call).unwrap_or(unit.line);
        out.push(model::AuthCheck {
            kind: effective_kind,
            callee: format!("(lifted cross-file {})", call.name),
            subjects,
            span: call.span,
            line,
            args: call.args.clone(),
            condition_text: None,
            is_route_level: false,
        });
    }
    out
}

fn auth_finding_to_diag(finding: &checks::AuthFinding, tree: &Tree, file_path: &Path) -> Diag {
    let point = byte_offset_to_point(tree, finding.span.0);
    Diag {
        path: file_path.to_string_lossy().into_owned(),
        line: point.row + 1,
        col: point.column + 1,
        severity: finding.severity,
        id: finding.rule_id.clone(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: Some(finding.message.clone()),
        labels: vec![],
        confidence: Some(Confidence::Medium),
        evidence: Some(Evidence {
            source: None,
            sink: Some(SpanEvidence {
                path: file_path.to_string_lossy().into_owned(),
                line: (point.row + 1) as u32,
                col: (point.column + 1) as u32,
                kind: "sink".into(),
                snippet: None,
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![],
            ..Default::default()
        }),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{VarTypes, apply_var_types_to_model, receiver_root, sink_class_for_type};
    use crate::auth_analysis::config::build_auth_rules;
    use crate::auth_analysis::model::{
        AnalysisUnit, AnalysisUnitKind, AuthorizationModel, OperationKind, SensitiveOperation,
        SinkClass,
    };
    use crate::ssa::type_facts::TypeKind;
    use crate::utils::config::Config;
    use std::collections::{HashMap, HashSet};

    fn sample_op(callee: &str, initial: Option<SinkClass>) -> SensitiveOperation {
        SensitiveOperation {
            kind: OperationKind::Mutation,
            sink_class: initial,
            callee: callee.to_string(),
            subjects: Vec::new(),
            span: (0, 0),
            line: 1,
            text: callee.to_string(),
        }
    }

    fn sample_unit(op: SensitiveOperation) -> AnalysisUnit {
        AnalysisUnit {
            kind: AnalysisUnitKind::Function,
            name: Some("handle".into()),
            span: (0, 0),
            params: Vec::new(),
            context_inputs: Vec::new(),
            call_sites: Vec::new(),
            auth_checks: Vec::new(),
            operations: vec![op],
            value_refs: Vec::new(),
            condition_texts: Vec::new(),
            line: 1,
            row_field_vars: HashMap::new(),
            var_alias_chain: HashMap::new(),
            row_population_data: HashMap::new(),
            self_actor_vars: HashSet::new(),
            self_actor_id_vars: HashSet::new(),
            authorized_sql_vars: HashSet::new(),
            const_bound_vars: HashSet::new(),
            typed_bounded_vars: HashSet::new(),
            typed_bounded_dto_fields: HashMap::new(),
            self_scoped_session_bases: HashSet::new(),
        }
    }

    #[test]
    fn receiver_root_returns_first_segment_only_for_chain_calls() {
        assert_eq!(receiver_root("map.insert"), Some("map"));
        assert_eq!(receiver_root("self.cache.insert"), Some("self"));
        // Free function call (no receiver) → None.
        assert_eq!(receiver_root("HashMap"), None);
        assert_eq!(receiver_root("free_fn"), None);
        // Empty chain segments → None.
        assert_eq!(receiver_root("."), None);
        assert_eq!(receiver_root(""), None);
    }

    #[test]
    fn sink_class_for_type_maps_security_typekinds() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        // LocalCollection always → InMemoryLocal.
        assert_eq!(
            sink_class_for_type(&TypeKind::LocalCollection, "whatever.insert", &rules),
            Some(SinkClass::InMemoryLocal)
        );
        // HttpClient → OutboundNetwork.
        assert_eq!(
            sink_class_for_type(&TypeKind::HttpClient, "client.send", &rules),
            Some(SinkClass::OutboundNetwork)
        );
        // DatabaseConnection: mutation verb → DbMutation.
        assert_eq!(
            sink_class_for_type(&TypeKind::DatabaseConnection, "conn.insert", &rules),
            Some(SinkClass::DbMutation)
        );
        // DatabaseConnection: read-only verb → DbCrossTenantRead.
        assert_eq!(
            sink_class_for_type(&TypeKind::DatabaseConnection, "conn.get", &rules),
            Some(SinkClass::DbCrossTenantRead)
        );
        // DatabaseConnection: unrecognized verb (`execute`) → DbMutation
        // (conservative default, treat as write-shaped).
        assert_eq!(
            sink_class_for_type(&TypeKind::DatabaseConnection, "conn.execute", &rules),
            Some(SinkClass::DbMutation)
        );
        // Non-security types → None (don't override).
        assert_eq!(
            sink_class_for_type(&TypeKind::String, "s.len", &rules),
            None
        );
        assert_eq!(
            sink_class_for_type(&TypeKind::Unknown, "x.frobnicate", &rules),
            None
        );
    }

    #[test]
    fn apply_var_types_overrides_sink_class_for_known_receiver() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        let mut model = AuthorizationModel::default();
        // Initial sink class from B1 name-based classification (e.g.
        // `results.insert` → DbMutation because `insert` matches the
        // mutation list and `results` doesn't match any non-sink prefix).
        model.units.push(sample_unit(sample_op(
            "results.insert",
            Some(SinkClass::DbMutation),
        )));

        let mut var_types: VarTypes = HashMap::new();
        var_types.insert("results".into(), TypeKind::LocalCollection);

        apply_var_types_to_model(&mut model, &rules, &var_types);

        // B2 overrode to InMemoryLocal based on the SSA type.
        assert_eq!(
            model.units[0].operations[0].sink_class,
            Some(SinkClass::InMemoryLocal)
        );
    }

    #[test]
    fn apply_var_types_leaves_classification_untouched_when_receiver_unknown() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        let mut model = AuthorizationModel::default();
        model.units.push(sample_unit(sample_op(
            "db.insert",
            Some(SinkClass::DbMutation),
        )));
        let var_types: VarTypes = HashMap::new();
        apply_var_types_to_model(&mut model, &rules, &var_types);
        // Unchanged, no entry in var_types for `db`.
        assert_eq!(
            model.units[0].operations[0].sink_class,
            Some(SinkClass::DbMutation)
        );
    }
}
