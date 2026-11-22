//! On-disk row shapes for the cross-file authorization fact sets.
//!
//! Two fact sets are harvested per file in pass 1 and consumed in pass 2:
//!
//! * [`super::caller_scope::CallerScopeEdge`] — one caller → callee edge per
//!   (caller unit, distinct callee leaf), folded into
//!   `GlobalSummaries.caller_scope_by_callee`.
//! * [`super::router_facts::PerFileRouterFacts`] — FastAPI router declarations
//!   and `include_router` edges, stored in
//!   `GlobalSummaries.router_facts_by_module`.
//!
//! The non-indexed path builds both in memory and folds them directly.  The
//! indexed path has to round-trip them through SQLite, which needs serde.
//!
//! # Why row types instead of serde on the in-memory types
//!
//! [`super::model::AuthCheck`] and its transitive members (`ValueRef`,
//! `CallSite`, `ValueSourceKind`) are analysis-internal: they are built,
//! mutated, and compared all over `auth_analysis`, and pinning a wire format
//! onto them would make every future field addition a silent schema change.
//! The established precedent in this crate is
//! [`super::model::AuthCheckSummary`], which keeps the in-memory type free of
//! wire concerns and sorts on serialize so the on-disk bytes do not move when
//! a `HashMap` iterates differently.  These rows follow it.
//!
//! # Losslessness is required, not merely nice
//!
//! `AuthCheckRow` carries **every** `AuthCheck` field.  It is tempting to keep
//! only what the route-level short-circuit reads, but
//! `auth_check_covers_subject` short-circuits on `is_route_level` while
//! `has_prior_collection_auth` matches `subjects` by canonical name with no
//! such short-circuit, and `check_token_override_without_validation` reads
//! `kind`.  A lossy row would make indexed scans diverge from non-indexed ones
//! on exactly the shapes this persistence exists to keep in parity.
//!
//! # Determinism
//!
//! `PerFileRouterFactsRow::local_router_deps` is a sorted `Vec`, not a
//! `HashMap`, so the serialized blob is byte-identical across runs for the
//! same input.  That keeps the per-file `file_hash` comparison meaningful and
//! stops a `HashMap` reordering from looking like a content change.

use serde::{Deserialize, Serialize};

use super::caller_scope::CallerScopeEdge;
use super::model::{AuthCheck, AuthCheckKind, CallSite, ValueRef, ValueSourceKind};
use super::router_facts::{PerFileRouterFacts, RouterIncludeEdge};
use crate::symbol::Lang;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueSourceKindRow {
    RequestParam,
    RequestBody,
    RequestQuery,
    Session,
    Identifier,
    MemberField,
    TokenField,
    ArrayIndex,
}

impl From<ValueSourceKind> for ValueSourceKindRow {
    fn from(k: ValueSourceKind) -> Self {
        match k {
            ValueSourceKind::RequestParam => Self::RequestParam,
            ValueSourceKind::RequestBody => Self::RequestBody,
            ValueSourceKind::RequestQuery => Self::RequestQuery,
            ValueSourceKind::Session => Self::Session,
            ValueSourceKind::Identifier => Self::Identifier,
            ValueSourceKind::MemberField => Self::MemberField,
            ValueSourceKind::TokenField => Self::TokenField,
            ValueSourceKind::ArrayIndex => Self::ArrayIndex,
        }
    }
}

impl From<ValueSourceKindRow> for ValueSourceKind {
    fn from(k: ValueSourceKindRow) -> Self {
        match k {
            ValueSourceKindRow::RequestParam => Self::RequestParam,
            ValueSourceKindRow::RequestBody => Self::RequestBody,
            ValueSourceKindRow::RequestQuery => Self::RequestQuery,
            ValueSourceKindRow::Session => Self::Session,
            ValueSourceKindRow::Identifier => Self::Identifier,
            ValueSourceKindRow::MemberField => Self::MemberField,
            ValueSourceKindRow::TokenField => Self::TokenField,
            ValueSourceKindRow::ArrayIndex => Self::ArrayIndex,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueRefRow {
    pub source_kind: ValueSourceKindRow,
    pub name: String,
    pub base: Option<String>,
    pub field: Option<String>,
    pub index: Option<String>,
    pub span: (usize, usize),
}

impl From<&ValueRef> for ValueRefRow {
    fn from(v: &ValueRef) -> Self {
        Self {
            source_kind: v.source_kind.into(),
            name: v.name.clone(),
            base: v.base.clone(),
            field: v.field.clone(),
            index: v.index.clone(),
            span: v.span,
        }
    }
}

impl From<ValueRefRow> for ValueRef {
    fn from(v: ValueRefRow) -> Self {
        Self {
            source_kind: v.source_kind.into(),
            name: v.name,
            base: v.base,
            field: v.field,
            index: v.index,
            span: v.span,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSiteRow {
    pub name: String,
    pub args: Vec<String>,
    pub span: (usize, usize),
    pub args_value_refs: Vec<Vec<ValueRefRow>>,
}

impl From<&CallSite> for CallSiteRow {
    fn from(c: &CallSite) -> Self {
        Self {
            name: c.name.clone(),
            args: c.args.clone(),
            span: c.span,
            args_value_refs: c
                .args_value_refs
                .iter()
                .map(|refs| refs.iter().map(ValueRefRow::from).collect())
                .collect(),
        }
    }
}

impl From<CallSiteRow> for CallSite {
    fn from(c: CallSiteRow) -> Self {
        Self {
            name: c.name,
            args: c.args,
            span: c.span,
            args_value_refs: c
                .args_value_refs
                .into_iter()
                .map(|refs| refs.into_iter().map(ValueRef::from).collect())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCheckRow {
    pub kind: AuthCheckKind,
    pub callee: String,
    pub subjects: Vec<ValueRefRow>,
    pub span: (usize, usize),
    pub line: usize,
    pub args: Vec<String>,
    pub condition_text: Option<String>,
    pub is_route_level: bool,
}

impl From<&AuthCheck> for AuthCheckRow {
    fn from(c: &AuthCheck) -> Self {
        Self {
            kind: c.kind,
            callee: c.callee.clone(),
            subjects: c.subjects.iter().map(ValueRefRow::from).collect(),
            span: c.span,
            line: c.line,
            args: c.args.clone(),
            condition_text: c.condition_text.clone(),
            is_route_level: c.is_route_level,
        }
    }
}

impl From<AuthCheckRow> for AuthCheck {
    fn from(c: AuthCheckRow) -> Self {
        Self {
            kind: c.kind,
            callee: c.callee,
            subjects: c.subjects.into_iter().map(ValueRef::from).collect(),
            span: c.span,
            line: c.line,
            args: c.args,
            condition_text: c.condition_text,
            is_route_level: c.is_route_level,
            // Only route-level checks are persisted; a body-dominating gate
            // is local to the function it was found in.
            dominates_body: false,
        }
    }
}

/// One persisted caller → callee edge.
///
/// `lang` is stored as [`Lang`] (already `Serialize`), keeping the row keyed
/// the same way `GlobalSummaries.caller_scope_by_callee` is: `(Lang, leaf)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerScopeEdgeRow {
    pub lang: Lang,
    pub callee_leaf: String,
    pub caller_authorized: bool,
    pub route_checks: Vec<AuthCheckRow>,
}

impl From<&CallerScopeEdge> for CallerScopeEdgeRow {
    fn from(e: &CallerScopeEdge) -> Self {
        Self {
            lang: e.lang,
            callee_leaf: e.callee_leaf.clone(),
            caller_authorized: e.caller_authorized,
            route_checks: e.route_checks.iter().map(AuthCheckRow::from).collect(),
        }
    }
}

impl From<CallerScopeEdgeRow> for CallerScopeEdge {
    fn from(e: CallerScopeEdgeRow) -> Self {
        Self {
            lang: e.lang,
            callee_leaf: e.callee_leaf,
            caller_authorized: e.caller_authorized,
            route_checks: e.route_checks.into_iter().map(AuthCheck::from).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterIncludeEdgeRow {
    pub parent_var: String,
    pub child_module_id: String,
    pub child_var: String,
    pub child_local: bool,
}

impl From<&RouterIncludeEdge> for RouterIncludeEdgeRow {
    fn from(e: &RouterIncludeEdge) -> Self {
        Self {
            parent_var: e.parent_var.clone(),
            child_module_id: e.child_module_id.clone(),
            child_var: e.child_var.clone(),
            child_local: e.child_local,
        }
    }
}

impl From<RouterIncludeEdgeRow> for RouterIncludeEdge {
    fn from(e: RouterIncludeEdgeRow) -> Self {
        Self {
            parent_var: e.parent_var,
            child_module_id: e.child_module_id,
            child_var: e.child_var,
            child_local: e.child_local,
        }
    }
}

/// Per-file router facts.
///
/// `local_router_deps` is sorted by router-var name on construction so the
/// serialized blob does not depend on `HashMap` iteration order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerFileRouterFactsRow {
    pub local_router_deps: Vec<(String, Vec<(CallSiteRow, bool)>)>,
    pub include_router_edges: Vec<RouterIncludeEdgeRow>,
}

impl From<&PerFileRouterFacts> for PerFileRouterFactsRow {
    fn from(f: &PerFileRouterFacts) -> Self {
        let mut local_router_deps: Vec<(String, Vec<(CallSiteRow, bool)>)> = f
            .local_router_deps
            .iter()
            .map(|(var, deps)| {
                (
                    var.clone(),
                    deps.iter()
                        .map(|(call, flag)| (CallSiteRow::from(call), *flag))
                        .collect(),
                )
            })
            .collect();
        local_router_deps.sort_by(|a, b| a.0.cmp(&b.0));
        Self {
            local_router_deps,
            include_router_edges: f
                .include_router_edges
                .iter()
                .map(RouterIncludeEdgeRow::from)
                .collect(),
        }
    }
}

impl From<PerFileRouterFactsRow> for PerFileRouterFacts {
    fn from(f: PerFileRouterFactsRow) -> Self {
        Self {
            local_router_deps: f
                .local_router_deps
                .into_iter()
                .map(|(var, deps)| {
                    (
                        var,
                        deps.into_iter()
                            .map(|(call, flag)| (CallSite::from(call), flag))
                            .collect(),
                    )
                })
                .collect(),
            include_router_edges: f
                .include_router_edges
                .into_iter()
                .map(RouterIncludeEdge::from)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_ref() -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::MemberField,
            name: "dag_run.id".into(),
            base: Some("dag_run".into()),
            field: Some("id".into()),
            index: None,
            span: (10, 20),
        }
    }

    fn auth_check() -> AuthCheck {
        AuthCheck {
            kind: AuthCheckKind::Ownership,
            callee: "requires_access_dag".into(),
            subjects: vec![value_ref()],
            span: (5, 40),
            line: 3,
            args: vec!["\"POST\"".into()],
            condition_text: Some("user.can_edit(dag)".into()),
            is_route_level: true,
            dominates_body: false,
        }
    }

    /// Every `AuthCheck` field has to survive the round trip: the consumers
    /// read `kind`, `subjects` and `is_route_level` on different code paths,
    /// so a dropped field shows up as an indexed-vs-non-indexed divergence
    /// rather than as a compile error.
    #[test]
    fn auth_check_row_round_trips_losslessly() {
        let original = auth_check();
        let back: AuthCheck = AuthCheckRow::from(&original).into();
        assert_eq!(back.kind, original.kind);
        assert_eq!(back.callee, original.callee);
        assert_eq!(back.subjects, original.subjects);
        assert_eq!(back.span, original.span);
        assert_eq!(back.line, original.line);
        assert_eq!(back.args, original.args);
        assert_eq!(back.condition_text, original.condition_text);
        assert_eq!(back.is_route_level, original.is_route_level);
    }

    #[test]
    fn caller_scope_edge_row_round_trips_through_messagepack() {
        let edge = CallerScopeEdge {
            lang: Lang::Python,
            callee_leaf: "fetch_dag_run".into(),
            caller_authorized: true,
            route_checks: vec![auth_check()],
        };
        let bytes = rmp_serde::to_vec(&CallerScopeEdgeRow::from(&edge)).unwrap();
        let row: CallerScopeEdgeRow = rmp_serde::from_slice(&bytes).unwrap();
        let back: CallerScopeEdge = row.into();
        assert_eq!(back.lang, edge.lang);
        assert_eq!(back.callee_leaf, edge.callee_leaf);
        assert_eq!(back.caller_authorized, edge.caller_authorized);
        assert_eq!(back.route_checks.len(), 1);
        assert_eq!(back.route_checks[0].callee, "requires_access_dag");
        assert!(back.route_checks[0].is_route_level);
    }

    /// The blob must not move when the source `HashMap` iterates differently,
    /// otherwise an unchanged file looks changed on every rescan.
    #[test]
    fn router_facts_row_blob_is_order_stable() {
        let call = CallSite {
            name: "Depends".into(),
            args: vec!["requires_access".into()],
            span: (0, 10),
            args_value_refs: vec![],
        };
        let mut a = PerFileRouterFacts::default();
        let mut b = PerFileRouterFacts::default();
        for var in ["z_router", "a_router", "m_router"] {
            a.local_router_deps
                .insert(var.into(), vec![(call.clone(), true)]);
        }
        // Same content, inserted in the opposite order.
        for var in ["m_router", "a_router", "z_router"].into_iter().rev() {
            b.local_router_deps
                .insert(var.into(), vec![(call.clone(), true)]);
        }
        let ba = rmp_serde::to_vec(&PerFileRouterFactsRow::from(&a)).unwrap();
        let bb = rmp_serde::to_vec(&PerFileRouterFactsRow::from(&b)).unwrap();
        assert_eq!(ba, bb, "serialized router facts must be order-stable");

        let back: PerFileRouterFacts = rmp_serde::from_slice::<PerFileRouterFactsRow>(&ba)
            .unwrap()
            .into();
        assert_eq!(back.local_router_deps.len(), 3);
        assert!(back.local_router_deps.contains_key("a_router"));
    }
}
