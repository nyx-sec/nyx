//! Graphene / graphene-django mutation authorization recognizer.
//!
//! Graphene mutations are **not** registered in any URL conf — they are
//! attached to a GraphQL schema (`class Mutation: order_cancel =
//! OrderCancel.Field()`), so the Django URL-routing extractor
//! ([`super::django`]) never sees them.  Authorization is instead
//! declared declaratively on the mutation class:
//!
//! ```python
//! class OrderCancel(BaseMutation):
//!     class Meta:
//!         permissions = (OrderPermissions.MANAGE_ORDERS,)
//!
//!     @classmethod
//!     def perform_mutation(cls, _root, info, /, *, id):
//!         order = cls.get_node_or_error(info, id, only_type=Order)
//!         ...                       # calls into graphql/order/mutations/utils.py helpers
//! ```
//!
//! graphene's metaclass reads `Meta.permissions` into
//! `cls._meta.permissions` and enforces it (`PermissionDenied` unless the
//! actor holds one of the listed RBAC permissions) *before* dispatching
//! to `perform_mutation` / `mutate`.  A non-empty `Meta.permissions` (or
//! `permission_classes`) is therefore **route-level RBAC**: the action
//! method and every helper it calls run only after the permission gate
//! has decided authorization.
//!
//! Without this recognizer, the action method's own DB operations and —
//! more importantly — every cross-file helper it delegates to
//! (`graphql/**/mutations/utils.py`, `order/tasks.py`, `*/management.py`)
//! fire `missing_ownership_check` / `token_override_without_validation`,
//! because nothing maps the permissioned mutation class to a recognised
//! authorized route handler.  This is the single largest Python auth FP
//! cluster in the corpus (saleor: 189 + 273 findings, 2026-06-11).
//!
//! # What this recognizer does
//!
//! For a class that (a) declares a **non-empty** `Meta.permissions` /
//! `permission_classes` collection literal AND (b) defines a graphene
//! action method in its body, mark each action method as a
//! [`AnalysisUnitKind::RouteHandler`] carrying a route-level `Other`
//! (+ `TokenExpiry` / `TokenRecipient`) [`AuthCheck`].  This makes:
//!
//!   * `checks::check_ownership_gaps` /
//!     `check_token_override_without_validation` short-circuit on the
//!     method's own body operations (route-level `Other` covers every
//!     subject; the two token checks satisfy the token-flow gate), and
//!   * [`super::super::caller_scope::extract_caller_scope_facts`] harvest
//!     the method's helper calls as *authorized* caller edges, so the
//!     cross-file (Phase 2) and in-file (Phase 1) caller-scope lifts
//!     suppress the helper FPs reached only from permissioned mutations.
//!
//! # Soundness — recall preservation
//!
//! The recognizer fires **only** when `Meta.permissions` /
//! `permission_classes` is a NON-EMPTY collection literal
//! (`tuple` / `list` / `set` with ≥ 1 element).  A mutation with no
//! `Meta.permissions`, or an empty `permissions = ()`, is a *public*
//! mutation and is left unauthorized, so `missing_ownership_check` still
//! fires on its id-targeted sinks (mirrors the DRF empty-`permission_classes`
//! handling in [`super::django`]).
//!
//! The action-method gate keeps the rule graphene-specific: a Django
//! *model* `class Meta: permissions = [("can_x", "…")]` carries the same
//! attribute name but has no graphene action method, so it is never
//! authorized.  And the abstract graphene base classes
//! (`BaseMutation`, `ModelMutation`, …) define `perform_mutation`/`mutate`
//! in their bodies but set `cls._meta.permissions` dynamically
//! (`_meta.permissions = permissions`, an *attribute* assignment, not an
//! identifier-named `permissions = (...)`), so they fail the declarative
//! gate and stay unauthorized.

use super::AuthExtractor;
use super::common::{
    build_function_unit, decorated_definition_child, named_children, span, text, visit_named_nodes,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{
    AnalysisUnit, AnalysisUnitKind, AuthCheck, AuthCheckKind, AuthorizationModel,
};
use crate::utils::project::FrameworkContext;
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct GrapheneExtractor;

/// graphene / graphene-django / relay mutation resolver entry points.
/// Presence of one of these methods **in the class body** (combined with
/// a non-empty `Meta.permissions`) is the graphene-mutation signal.
/// `perform_mutation` (graphene-django), `mutate` (graphene core),
/// `mutate_and_get_payload` (relay `ClientIDMutation`), and
/// `perform_bulk_mutation` (graphene-django bulk) are all graphene-owned
/// names — a class defining one is unambiguously a mutation, not an
/// ORM model that merely happens to set `Meta.permissions`.
const GRAPHENE_ACTION_METHODS: &[&str] = &[
    "perform_mutation",
    "mutate",
    "mutate_and_get_payload",
    "perform_bulk_mutation",
];

impl AuthExtractor for GrapheneExtractor {
    fn supports(&self, lang: &str, _framework_ctx: Option<&FrameworkContext>) -> bool {
        // graphene runs under Django, Flask, and Starlette / FastAPI, so
        // gate on language only rather than a single web framework.  The
        // walk is a cheap no-op on python files that contain no graphene
        // mutation class (the `Meta.permissions` + action-method gate
        // rejects ordinary classes immediately).
        lang == "python"
    }

    fn extract(
        &self,
        tree: &Tree,
        bytes: &[u8],
        _path: &Path,
        rules: &AuthAnalysisRules,
        model: &mut AuthorizationModel,
    ) {
        let root = tree.root_node();
        visit_named_nodes(root, &mut |node| {
            if node.kind() == "class_definition" {
                maybe_collect_graphene_mutation(node, bytes, rules, model);
            }
        });
    }
}

/// Recognise a single `class_definition` as a permissioned graphene
/// mutation and, when it matches, push one `RouteHandler` unit per
/// graphene action method defined in its body.
fn maybe_collect_graphene_mutation(
    class_def: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let Some(body) = class_def.child_by_field_name("body") else {
        return;
    };

    // Gate 1: a non-empty `Meta.permissions` / `permission_classes`.
    if !class_has_nonempty_permissions(body, bytes) {
        return;
    }

    let class_name = class_def
        .child_by_field_name("name")
        .map(|name| text(name, bytes));

    // Gate 2 (per method): a graphene action method defined in the body.
    for child in named_children(body) {
        let Some((method_node, method_name)) = action_method(child, bytes) else {
            continue;
        };

        let route_name = match &class_name {
            Some(cls) => format!("{cls}.{method_name}"),
            None => method_name,
        };
        let mut unit = build_function_unit(
            method_node,
            AnalysisUnitKind::RouteHandler,
            Some(route_name),
            bytes,
            rules,
        );
        let line = method_node.start_position().row + 1;
        push_meta_permission_checks(&mut unit, span(method_node), line);
        model.units.push(unit);
    }
}

/// If `child` is a graphene action method (a `function_definition` or a
/// `@classmethod`-decorated one whose name is in [`GRAPHENE_ACTION_METHODS`]),
/// return the definition node (the `decorated_definition` wrapper when
/// present, so [`build_function_unit`]'s span covers the decorators) and
/// the method name.
fn action_method<'tree>(child: Node<'tree>, bytes: &[u8]) -> Option<(Node<'tree>, String)> {
    let definition = match child.kind() {
        "function_definition" => child,
        "decorated_definition" => {
            let inner = decorated_definition_child(child)?;
            if inner.kind() != "function_definition" {
                return None;
            }
            inner
        }
        _ => return None,
    };
    let name = text(definition.child_by_field_name("name")?, bytes);
    if GRAPHENE_ACTION_METHODS.contains(&name.as_str()) {
        Some((child, name))
    } else {
        None
    }
}

/// Does the class body declare an inner `class Meta:` carrying a
/// **non-empty** `permissions = (...)` / `permission_classes = [...]`
/// collection literal?
///
/// Only an identifier-named left-hand side (`permissions`) with a
/// `tuple` / `list` / `set` right-hand side of ≥ 1 element counts.  This
/// deliberately rejects:
///   * the dynamic base-class form `_meta.permissions = permissions`
///     (left is an *attribute*, not the identifier `permissions`), and
///   * an empty `permissions = ()` (public mutation — recall preserved).
fn class_has_nonempty_permissions(class_body: Node<'_>, bytes: &[u8]) -> bool {
    for child in named_children(class_body) {
        if child.kind() != "class_definition" {
            continue;
        }
        let is_meta = child
            .child_by_field_name("name")
            .map(|name| text(name, bytes))
            .as_deref()
            == Some("Meta");
        if !is_meta {
            continue;
        }
        let Some(meta_body) = child.child_by_field_name("body") else {
            continue;
        };
        for stmt in named_children(meta_body) {
            let assign = match stmt.kind() {
                "assignment" => Some(stmt),
                "expression_statement" => named_children(stmt)
                    .into_iter()
                    .find(|n| n.kind() == "assignment"),
                _ => None,
            };
            let Some(assign) = assign else {
                continue;
            };
            let Some(left) = assign.child_by_field_name("left") else {
                continue;
            };
            let left_name = text(left, bytes);
            if left_name != "permissions" && left_name != "permission_classes" {
                continue;
            }
            let Some(right) = assign.child_by_field_name("right") else {
                continue;
            };
            if collection_is_nonempty(right) {
                return true;
            }
        }
    }
    false
}

/// True for a `tuple` / `list` / `set` literal with at least one element.
fn collection_is_nonempty(node: Node<'_>) -> bool {
    matches!(node.kind(), "tuple" | "list" | "set") && node.named_child_count() > 0
}

/// Push the route-level RBAC checks synthesised from a non-empty
/// `Meta.permissions`.
///
/// `Other` authorizes every subject the action method touches
/// (`auth_check_covers_subject` short-circuits `true` for route-level
/// non-login checks).  `TokenExpiry` + `TokenRecipient` satisfy the
/// `token_override_without_validation` gate the same way the FastAPI
/// scoped-`Security` recogniser does (see
/// [`super::flask::inject_middleware_auth`]): a class-level RBAC gate
/// means the action runs under an authenticated, authorized actor, so
/// the anonymous-token-acceptance concern that rule reasons about does
/// not apply.  All three are `is_route_level = true` so they are also
/// lifted onto cross-file / in-file helper units by the caller-scope
/// passes.
fn push_meta_permission_checks(unit: &mut AnalysisUnit, span: (usize, usize), line: usize) {
    const CALLEE: &str = "(graphene Meta.permissions)";
    for kind in [
        AuthCheckKind::Other,
        AuthCheckKind::TokenExpiry,
        AuthCheckKind::TokenRecipient,
    ] {
        unit.auth_checks.push(AuthCheck {
            kind,
            callee: CALLEE.to_string(),
            subjects: Vec::new(),
            span,
            line,
            args: Vec::new(),
            condition_text: None,
            is_route_level: true,
            dominates_body: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_analysis::config::build_auth_rules;
    use crate::utils::config::Config;

    fn analyse(src: &str) -> AuthorizationModel {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let rules = build_auth_rules(&Config::default(), "python");
        let mut model = AuthorizationModel {
            lang: "python".into(),
            ..Default::default()
        };
        GrapheneExtractor.extract(
            &tree,
            src.as_bytes(),
            Path::new("mutations.py"),
            &rules,
            &mut model,
        );
        model
    }

    const PERMISSIONED: &str = r#"
class OrderCancel(BaseMutation):
    class Arguments:
        id = graphene.ID(required=True)

    class Meta:
        description = "Cancel an order."
        permissions = (OrderPermissions.MANAGE_ORDERS,)

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        order = cls.get_node_or_error(info, id, only_type=Order)
        return cancel_order(order)
"#;

    #[test]
    fn permissioned_mutation_marks_action_method_route_handler_with_route_level_other() {
        let model = analyse(PERMISSIONED);
        let unit = model
            .units
            .iter()
            .find(|u| u.name.as_deref() == Some("OrderCancel.perform_mutation"))
            .expect("perform_mutation must become a unit");
        assert_eq!(unit.kind, AnalysisUnitKind::RouteHandler);
        assert!(
            unit.auth_checks
                .iter()
                .any(|c| c.is_route_level && c.kind == AuthCheckKind::Other),
            "must carry a route-level Other check"
        );
        assert!(
            unit.auth_checks
                .iter()
                .any(|c| c.is_route_level && c.kind == AuthCheckKind::TokenExpiry),
            "must carry a route-level TokenExpiry check"
        );
        assert!(
            unit.auth_checks
                .iter()
                .any(|c| c.is_route_level && c.kind == AuthCheckKind::TokenRecipient),
            "must carry a route-level TokenRecipient check"
        );
        // The helper call is harvested onto the unit's call_sites so the
        // caller-scope passes can mark it an authorized caller edge.
        assert!(
            unit.call_sites
                .iter()
                .any(|c| c.name.rsplit('.').next() == Some("cancel_order")),
            "helper call must be present for caller-scope harvest"
        );
    }

    /// Public mutation (no `Meta.permissions`): recall must be preserved,
    /// the action method must NOT be authorized.
    #[test]
    fn public_mutation_without_permissions_is_not_authorized() {
        let src = r#"
class PublicThing(BaseMutation):
    class Meta:
        description = "no permissions here"

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        return Thing.objects.get(id=id)
"#;
        let model = analyse(src);
        assert!(
            model.units.is_empty(),
            "public mutation must not produce a RouteHandler unit"
        );
    }

    /// Empty `permissions = ()` is a public mutation — recall preserved.
    #[test]
    fn empty_permissions_tuple_is_not_authorized() {
        let src = r#"
class PublicThing(BaseMutation):
    class Meta:
        permissions = ()

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        return Thing.objects.get(id=id)
"#;
        let model = analyse(src);
        assert!(
            model.units.is_empty(),
            "empty permissions tuple must not authorize"
        );
    }

    /// A Django *model* with `class Meta: permissions = [(...)]` but no
    /// graphene action method must NOT be recognised as a mutation.
    #[test]
    fn django_model_meta_permissions_without_action_method_is_ignored() {
        let src = r#"
class Order(models.Model):
    class Meta:
        permissions = [("manage_orders", "Can manage orders")]

    def can_cancel(self):
        return True
"#;
        let model = analyse(src);
        assert!(
            model.units.is_empty(),
            "ORM model permissions without a graphene action method must be ignored"
        );
    }

    /// The dynamic base-class form `_meta.permissions = permissions`
    /// (attribute LHS) must not satisfy the declarative gate, so an
    /// abstract base defining `perform_mutation` stays unauthorized.
    #[test]
    fn dynamic_meta_attribute_assignment_does_not_authorize() {
        let src = r#"
class BaseMutation(graphene.Mutation):
    class Meta:
        abstract = True

    @classmethod
    def __init_subclass_with_meta__(cls, permissions=None, **kwargs):
        _meta.permissions = permissions

    @classmethod
    def perform_mutation(cls, _root, info):
        raise NotImplementedError
"#;
        let model = analyse(src);
        assert!(
            model.units.is_empty(),
            "dynamic `_meta.permissions = ...` must not authorize an abstract base"
        );
    }

    /// `permission_classes = [...]` is also recognised (DRF-style inside a
    /// graphene mutation).
    #[test]
    fn permission_classes_list_is_recognised() {
        let src = r#"
class ThingMutation(BaseMutation):
    class Meta:
        permission_classes = [IsAdminUser]

    @classmethod
    def mutate(cls, root, info, **data):
        return Thing.objects.filter(id=data["id"])
"#;
        let model = analyse(src);
        let unit = model
            .units
            .iter()
            .find(|u| u.name.as_deref() == Some("ThingMutation.mutate"))
            .expect("mutate must become a unit");
        assert_eq!(unit.kind, AnalysisUnitKind::RouteHandler);
        assert!(
            unit.auth_checks
                .iter()
                .any(|c| c.is_route_level && c.kind == AuthCheckKind::Other)
        );
    }
}
