//! Cross-file caller-scope IPA (Phase 2 of the caller-scope fix).
//!
//! `apply_caller_scope_propagation` propagates route-handler
//! auth checks DOWN onto callee helper units, but only within a single
//! file: it refuses to lift onto a helper that has no in-file caller
//! (the helper could be an external entry point).  The dominant FP shape
//! on FastAPI / Django / Flask codebases (sentry, saleor, airflow) is
//! cross-file: the authorized route handler lives in `api/endpoints.py`
//! and delegates the actual sink to a private helper in
//! `api/services.py` / `utils.py` / `tasks.py`.  The helper has no
//! in-file caller at all, so Phase 1 always refuses — every
//! `Model.objects.filter(id=...)` / `session.add(...)` it contains fires
//! `missing_ownership_check` / `token_override_without_validation`.
//!
//! This module closes that gap (single-hop) by accumulating, during
//! pass 1, the auth status of every caller of every callee leaf across
//! the whole index.  At pass 2 a helper inherits its callers' route-level
//! checks iff EVERY observed caller is an authorized route handler — the
//! same soundness rule Phase 1 applies in-file, lifted to the
//! cross-file caller set.
//!
//! # Soundness
//!
//! The accumulator under-approximates "authorized": a caller is recorded
//! authorized only when its pass-1 model already carries a route-level
//! non-Login seed check (inline decorator / same-file router dep).  A
//! route authorized only via a cross-file router-include dep (resolved at
//! pass 2, not pass 1) is recorded UNAUTHORIZED here — which only
//! *refuses* a lift (residual FP), never suppresses a real finding.
//! Treating an actually-unauthorized caller as authorized never happens,
//! because the authorized flag is only set from a concrete seed check.
//!
//! Leaf-name keying (`(Lang, leaf)`) over-merges callers of distinct
//! same-named functions.  Over-merging only makes the `all_authorized`
//! conjunction MORE likely to be false (more callers in the set), so it
//! is conservative: it can refuse a legitimate lift (residual FP) but
//! never authorizes a helper whose real caller set includes an
//! unauthorized caller (that caller's edge is in the set and forces
//! `all_authorized = false`).
//!
//! # Limitations (documented follow-ups)
//!
//! - Single-hop only.  A transitive cross-file chain
//!   `route(A) → mid(B) → leaf(C)` does not lift onto `leaf`: `mid` is a
//!   helper with no route-level seed check, so it is recorded as an
//!   unauthorized caller of `leaf`.  Phase 1 covers the transitive case
//!   *within* a file; the cross-file transitive case needs a topological
//!   / SCC fixed-point over caller-auth facts.
//!
//! Both scan paths are covered.  The non-indexed path folds the accumulator
//! in memory from [`crate::ast::analyse_file_fused`]; the indexed path
//! persists the raw per-file edges (see [`super::persist`]) and replays them
//! through the same [`crate::summary::GlobalSummaries::fold_caller_scope_edge`]
//! entry point, so the merge semantics are identical by construction.
//! `tests/indexed_parity_tests.rs` locks that with cold and warm parity cases.

use crate::symbol::Lang;

use super::model::{AnalysisUnitKind, AuthCheck, AuthCheckKind, AuthorizationModel};

/// Is cross-file caller-scope IPA enabled?  Default on; set
/// `NYX_XFILE_CALLER_SCOPE=0` (or `false`) to disable — an escape hatch
/// matching the `NYX_CONTEXT_SENSITIVE` convention, useful for A/B
/// measuring the lift's corpus delta against a single binary.
pub fn cross_file_enabled() -> bool {
    match std::env::var("NYX_XFILE_CALLER_SCOPE") {
        Ok(v) => {
            let v = v.trim();
            !(v == "0" || v.eq_ignore_ascii_case("false"))
        }
        Err(_) => true,
    }
}

/// A route-level auth check kind strong enough to *seed* authorization.
///
/// Mirrors the `is_seed_kind` rule in
/// [`super::apply_caller_scope_propagation`]: `LoginGuard` alone proves
/// only identity (not authority), and `TokenExpiry` / `TokenRecipient`
/// alone do not justify foreign-id mutations — those kinds are already
/// filtered out by `has_prior_subject_auth`.
fn is_seed_kind(k: AuthCheckKind) -> bool {
    !matches!(
        k,
        AuthCheckKind::LoginGuard | AuthCheckKind::TokenExpiry | AuthCheckKind::TokenRecipient
    )
}

/// One caller → callee edge harvested in pass 1.
///
/// `caller_authorized` is the auth status of the *enclosing* unit; every
/// call site contributes an edge (including unauthorized callers, whose
/// edge forces the callee's `all_authorized` conjunction to `false`).
#[derive(Debug, Clone)]
pub struct CallerScopeEdge {
    pub lang: Lang,
    pub callee_leaf: String,
    pub caller_authorized: bool,
    /// Route-level (non-`LoginGuard`) checks to lift onto the callee when
    /// every caller is authorized.  Empty for unauthorized callers.
    pub route_checks: Vec<AuthCheck>,
}

/// Cross-file accumulator stored in `GlobalSummaries`, keyed by
/// `(Lang, callee_leaf)`.
///
/// Associative + commutative so it folds safely under rayon `reduce`:
/// `has_caller` is OR, `all_authorized` is AND (default `true` is the AND
/// identity so empty/merged accumulators don't corrupt the conjunction),
/// `lifted_checks` is a union.
#[derive(Debug, Clone)]
pub struct CalleeCallerAcc {
    /// At least one caller of this leaf was observed anywhere in the index.
    pub has_caller: bool,
    /// AND across every observed caller's `caller_authorized` flag.
    pub all_authorized: bool,
    /// Union of route-level checks contributed by authorized callers.
    pub lifted_checks: Vec<AuthCheck>,
}

impl Default for CalleeCallerAcc {
    fn default() -> Self {
        Self {
            has_caller: false,
            all_authorized: true,
            lifted_checks: Vec::new(),
        }
    }
}

impl CalleeCallerAcc {
    /// Fold one caller edge into the accumulator.
    pub fn fold_edge(&mut self, authorized: bool, checks: &[AuthCheck]) {
        self.has_caller = true;
        self.all_authorized &= authorized;
        if authorized {
            self.lifted_checks.extend(checks.iter().cloned());
        }
    }

    /// Merge another accumulator (rayon `reduce` / DB-load combine).
    pub fn merge(&mut self, other: CalleeCallerAcc) {
        self.has_caller |= other.has_caller;
        self.all_authorized &= other.all_authorized;
        self.lifted_checks.extend(other.lifted_checks);
    }

    /// Should a helper with this accumulator inherit the lifted checks?
    /// Requires at least one observed caller, every caller authorized,
    /// and a non-empty lift set.
    pub fn should_lift(&self) -> bool {
        self.has_caller && self.all_authorized && !self.lifted_checks.is_empty()
    }
}

/// Harvest pass-1 caller-scope edges from a per-file authorization model.
///
/// One edge per (caller-unit, distinct callee-leaf) pair.  Self-recursive
/// calls are skipped (a tautological self-cover).  Both route handlers
/// and helper functions emit edges: an unauthorized helper caller is
/// essential to soundness — it forces the inner callee's `all_authorized`
/// conjunction to `false`, refusing the lift exactly as Phase 1 refuses a
/// helper reached from an un-lifted helper.
pub fn extract_caller_scope_facts(model: &AuthorizationModel, lang: Lang) -> Vec<CallerScopeEdge> {
    use std::collections::HashSet;

    let mut edges = Vec::new();
    for unit in &model.units {
        let authorized = unit
            .auth_checks
            .iter()
            .any(|c| c.is_route_level && is_seed_kind(c.kind));
        // Lift ALL route-level non-Login checks (matching Phase 1's
        // `unit_route_level_checks`): `TokenExpiry` / `TokenRecipient` are
        // carried alongside the seed kinds because
        // `check_token_override_without_validation` gates on them
        // separately from `has_prior_subject_auth`.
        let route_checks: Vec<AuthCheck> = if authorized {
            unit.auth_checks
                .iter()
                .filter(|c| c.is_route_level && c.kind != AuthCheckKind::LoginGuard)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        let self_leaf = unit
            .name
            .as_deref()
            .map(|n| n.rsplit('.').next().unwrap_or(n));

        let mut seen: HashSet<&str> = HashSet::new();
        for call in &unit.call_sites {
            let leaf = call.name.rsplit('.').next().unwrap_or(&call.name);
            if leaf.is_empty() {
                continue;
            }
            if self_leaf == Some(leaf) {
                continue;
            }
            if !seen.insert(leaf) {
                continue;
            }
            edges.push(CallerScopeEdge {
                lang,
                callee_leaf: leaf.to_string(),
                caller_authorized: authorized,
                route_checks: route_checks.clone(),
            });
        }
    }
    edges
}

/// Lift cross-file caller-scope checks onto every eligible helper unit in
/// `model`.
///
/// For each non-route-handler unit, look up the cross-file accumulator by
/// `(lang, leaf)`.  When `should_lift()` holds, append the accumulated
/// route-level checks as synthetic `is_route_level=true` AuthChecks,
/// re-anchored at the unit's start line so `has_prior_subject_auth`'s
/// `check.line <= op.line` gate covers every operation inside the unit —
/// matching `apply_caller_scope_propagation`'s final lift loop.
///
/// Called BEFORE the in-file caller-scope pass so a cross-file-lifted
/// helper (now carrying route-level seed checks) can itself seed the
/// in-file fixed point onto its same-file sub-callees.
pub fn apply_cross_file_caller_scope(
    model: &mut AuthorizationModel,
    lang: Lang,
    resolve: impl Fn(Lang, &str) -> Option<CalleeCallerAcc>,
) {
    use std::collections::HashSet;

    for unit in &mut model.units {
        if unit.kind == AnalysisUnitKind::RouteHandler {
            continue;
        }
        let Some(name) = unit.name.as_deref() else {
            continue;
        };
        let leaf = name.rsplit('.').next().unwrap_or(name);
        if leaf.is_empty() {
            continue;
        }
        let Some(acc) = resolve(lang, leaf) else {
            continue;
        };
        if !acc.should_lift() {
            continue;
        }
        let mut existing_keys: HashSet<((usize, usize), AuthCheckKind, String)> = unit
            .auth_checks
            .iter()
            .map(|c| (c.span, c.kind, c.callee.clone()))
            .collect();
        for check in acc.lifted_checks {
            let mut synth = check;
            synth.line = unit.line;
            synth.callee = format!("(cross-file caller-scope lift {})", synth.callee);
            let key = (synth.span, synth.kind, synth.callee.clone());
            if existing_keys.insert(key) {
                unit.auth_checks.push(synth);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_analysis::model::{AnalysisUnit, CallSite, UnitRuntime};
    use std::collections::{HashMap, HashSet};

    fn route_level_check(kind: AuthCheckKind) -> AuthCheck {
        AuthCheck {
            kind,
            callee: "require_auth".to_string(),
            subjects: Vec::new(),
            span: (0, 0),
            line: 1,
            args: Vec::new(),
            condition_text: None,
            is_route_level: true,
            dominates_body: false,
        }
    }

    fn unit(
        name: &str,
        kind: AnalysisUnitKind,
        checks: Vec<AuthCheck>,
        callees: &[&str],
    ) -> AnalysisUnit {
        AnalysisUnit {
            kind,
            name: Some(name.into()),
            span: (0, 0),
            params: Vec::new(),
            context_inputs: Vec::new(),
            call_sites: callees
                .iter()
                .map(|c| CallSite {
                    name: (*c).to_string(),
                    args: Vec::new(),
                    span: (0, 0),
                    args_value_refs: Vec::new(),
                })
                .collect(),
            auth_checks: checks,
            operations: Vec::new(),
            value_refs: Vec::new(),
            condition_texts: Vec::new(),
            line: 1,
            row_field_vars: HashMap::new(),
            var_alias_chain: HashMap::new(),
            row_population_data: HashMap::new(),
            row_derived_from: HashMap::new(),
            row_fetch_callees: HashMap::new(),
            self_actor_vars: HashSet::new(),
            self_actor_id_vars: HashSet::new(),
            authorized_sql_vars: HashSet::new(),
            const_bound_vars: HashSet::new(),
            typed_bounded_vars: HashSet::new(),
            typed_bounded_dto_fields: HashMap::new(),
            self_scoped_session_bases: HashSet::new(),
            injected_params: HashSet::new(),
            is_nextauth_options_factory: false,
            package_names: HashSet::new(),
            runtime: UnitRuntime::Unknown,
            internal_helper: false,
            request_roots: HashSet::new(),
            request_scope_roots: HashSet::new(),
            authorization_scoped_vars: HashSet::new(),
        }
    }

    fn model_of(units: Vec<AnalysisUnit>) -> AuthorizationModel {
        AuthorizationModel {
            units,
            ..Default::default()
        }
    }

    #[test]
    fn authorized_route_emits_authorized_edge_for_each_callee() {
        let route = unit(
            "ti_update_state",
            AnalysisUnitKind::RouteHandler,
            vec![route_level_check(AuthCheckKind::Other)],
            &["create_state_update", "create_state_update", "log_event"],
        );
        let edges = extract_caller_scope_facts(&model_of(vec![route]), Lang::Python);
        // Distinct leaves only: create_state_update, log_event.
        assert_eq!(edges.len(), 2);
        assert!(edges.iter().all(|e| e.caller_authorized));
        let cse = edges
            .iter()
            .find(|e| e.callee_leaf == "create_state_update")
            .unwrap();
        assert_eq!(cse.route_checks.len(), 1);
        assert_eq!(cse.route_checks[0].kind, AuthCheckKind::Other);
    }

    #[test]
    fn unauthorized_helper_caller_emits_unauthorized_edge_with_no_checks() {
        let helper = unit(
            "mid_helper",
            AnalysisUnitKind::Function,
            vec![],
            &["leaf_helper"],
        );
        let edges = extract_caller_scope_facts(&model_of(vec![helper]), Lang::Python);
        assert_eq!(edges.len(), 1);
        assert!(!edges[0].caller_authorized);
        assert!(edges[0].route_checks.is_empty());
    }

    #[test]
    fn login_guard_only_route_is_not_authorized() {
        let route = unit(
            "list_things",
            AnalysisUnitKind::RouteHandler,
            vec![route_level_check(AuthCheckKind::LoginGuard)],
            &["fetch_things"],
        );
        let edges = extract_caller_scope_facts(&model_of(vec![route]), Lang::Python);
        assert_eq!(edges.len(), 1);
        assert!(
            !edges[0].caller_authorized,
            "LoginGuard alone must not seed authorization"
        );
    }

    #[test]
    fn self_recursive_call_is_skipped() {
        let f = unit(
            "recurse",
            AnalysisUnitKind::Function,
            vec![],
            &["recurse", "other"],
        );
        let edges = extract_caller_scope_facts(&model_of(vec![f]), Lang::Python);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].callee_leaf, "other");
    }

    #[test]
    fn acc_all_authorized_only_when_every_caller_authorized() {
        let mut acc = CalleeCallerAcc::default();
        let chk = vec![route_level_check(AuthCheckKind::Other)];
        acc.fold_edge(true, &chk);
        assert!(acc.should_lift());
        // A single unauthorized caller poisons the conjunction.
        acc.fold_edge(false, &[]);
        assert!(!acc.should_lift());
        assert!(acc.has_caller);
        assert!(!acc.all_authorized);
    }

    #[test]
    fn acc_merge_is_conservative_and_unions_checks() {
        let chk_a = vec![route_level_check(AuthCheckKind::Other)];
        let chk_b = vec![route_level_check(AuthCheckKind::Membership)];
        let mut a = CalleeCallerAcc::default();
        a.fold_edge(true, &chk_a);
        let mut b = CalleeCallerAcc::default();
        b.fold_edge(true, &chk_b);
        a.merge(b);
        assert!(a.should_lift());
        assert_eq!(a.lifted_checks.len(), 2);

        // Merging in an unauthorized branch refuses the lift.
        let mut c = CalleeCallerAcc::default();
        c.fold_edge(false, &[]);
        a.merge(c);
        assert!(!a.should_lift());
    }

    #[test]
    fn empty_default_acc_merge_does_not_authorize() {
        // Default acc (all_authorized=true identity, has_caller=false)
        // must never authorize on its own.
        let acc = CalleeCallerAcc::default();
        assert!(!acc.should_lift(), "no observed caller => no lift");
        // And merging an empty default into an unauthorized acc keeps it
        // unauthorized (AND identity preserved).
        let mut unauth = CalleeCallerAcc::default();
        unauth.fold_edge(false, &[]);
        unauth.merge(CalleeCallerAcc::default());
        assert!(!unauth.should_lift());
    }

    #[test]
    fn lift_applies_route_checks_to_helper_unit() {
        let mut helper = model_of(vec![unit(
            "create_state_update",
            AnalysisUnitKind::Function,
            vec![],
            &["session_add"],
        )]);
        let lifted = std::cell::Cell::new(false);
        apply_cross_file_caller_scope(&mut helper, Lang::Python, |_, leaf| {
            if leaf == "create_state_update" {
                lifted.set(true);
                let mut acc = CalleeCallerAcc::default();
                acc.fold_edge(true, &[route_level_check(AuthCheckKind::Other)]);
                Some(acc)
            } else {
                None
            }
        });
        assert!(lifted.get());
        let u = &helper.units[0];
        assert!(
            u.auth_checks
                .iter()
                .any(|c| c.is_route_level && c.kind == AuthCheckKind::Other),
            "helper must inherit the route-level check"
        );
        assert!(
            u.auth_checks[0]
                .callee
                .contains("cross-file caller-scope lift"),
            "synthetic check must be tagged"
        );
    }

    #[test]
    fn lift_skips_route_handler_units() {
        let mut m = model_of(vec![unit(
            "a_route",
            AnalysisUnitKind::RouteHandler,
            vec![],
            &[],
        )]);
        apply_cross_file_caller_scope(&mut m, Lang::Python, |_, _| {
            let mut acc = CalleeCallerAcc::default();
            acc.fold_edge(true, &[route_level_check(AuthCheckKind::Other)]);
            Some(acc)
        });
        assert!(
            m.units[0].auth_checks.is_empty(),
            "route handlers are never lift targets"
        );
    }

    #[test]
    fn lift_refuses_when_not_all_callers_authorized() {
        let mut m = model_of(vec![unit(
            "helper",
            AnalysisUnitKind::Function,
            vec![],
            &[],
        )]);
        apply_cross_file_caller_scope(&mut m, Lang::Python, |_, _| {
            let mut acc = CalleeCallerAcc::default();
            acc.fold_edge(true, &[route_level_check(AuthCheckKind::Other)]);
            acc.fold_edge(false, &[]);
            Some(acc)
        });
        assert!(
            m.units[0].auth_checks.is_empty(),
            "a mixed caller set must not lift"
        );
    }
}
