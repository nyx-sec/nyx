//! Cross-file FastAPI router-dependency tracking.
//!
//! FastAPI propagates `dependencies=[Security(...), Depends(...)]` declared
//! at the router level onto every route attached to that router, including
//! routes attached via cross-file `<parent>.include_router(<child>.router)`
//! lifts.  The per-file router-dep collector in
//! [`crate::auth_analysis::extract::flask::collect_router_level_dependencies`]
//! sees only the file under analysis, so a bare child router whose auth is
//! declared on a parent router in `__init__.py` (canonical airflow shape) has
//! no visible deps.  This module captures the cross-file edges + parent
//! declarations during pass 1 and resolves them into a per-child effective
//! dep map for pass 2's auth analysis.
//!
//! Storage shape: per-Python-file [`PerFileRouterFacts`] with
//! [`local_router_deps`] (the `<router> = X(deps=[…])` declarations
//! visible in the file) and [`include_router_edges`] (the
//! `<parent>.include_router(<child_module>.<child_var>, …)` calls).
//! Persisted into [`crate::summary::GlobalSummaries::router_facts_by_module`]
//! during pass 1 and resolved into the active file's
//! [`crate::auth_analysis::model::AuthorizationModel::cross_file_router_deps`]
//! at pass 2 entry.
//!
//! Module identity: file basename without `.py`.  This is approximate (two
//! files named `task_instances.py` in different packages would collide) but
//! covers airflow-style codebases where include_router targets reference the
//! child's module name directly (`task_instances.router`).  Transitive lifts
//! (`grandparent.include_router(parent); parent.include_router(child)`) are
//! resolved by walking the index iteratively at lookup time.

use crate::auth_analysis::extract::common::{
    call_site_from_node, named_children, string_literal_value, text,
};
use crate::auth_analysis::model::CallSite;
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

/// Per-file extracted router declarations + include_router edges.
/// Persisted into `GlobalSummaries.router_facts_by_module` keyed by the
/// file's [`module_id_for_path`].  Single-purpose: drives the cross-file
/// router-dep resolution at pass 2 entry.
#[derive(Debug, Clone, Default)]
pub struct PerFileRouterFacts {
    /// Local router var → declared inline `dependencies=[...]` deps.
    /// Mirrors `flask::collect_router_level_dependencies` output.
    pub local_router_deps: HashMap<String, Vec<(CallSite, bool)>>,
    /// `<parent>.include_router(<child_module>.<child_var>, ...)` edges
    /// observed in this file.  Each edge specifies a parent router var
    /// (local to this file) and a child router identified by its
    /// module_id + var name.  Cross-file lookups walk these.
    pub include_router_edges: Vec<RouterIncludeEdge>,
}

/// A single `<parent>.include_router(<child_module>.<child_var>, ...)`
/// edge.  `parent_var` is the local variable that owns the deps to lift;
/// `child_module_id` + `child_var` together name the child router whose
/// routes inherit the parent's deps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterIncludeEdge {
    pub parent_var: String,
    pub child_module_id: String,
    pub child_var: String,
}

/// Translate a file path into a stable cross-file module identifier.
///
/// Currently the file's basename without the `.py` extension — sufficient
/// for the airflow shape (`from . import task_instances; …
/// authenticated_router.include_router(task_instances.router)`) where the
/// include_router target's module reference is the child file's own
/// basename.  Returns `None` for files whose stem is `__init__`
/// (parent files don't need to be looked up; they emit edges only) or
/// for paths with no usable stem.
pub fn module_id_for_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    if stem.is_empty() || stem == "__init__" {
        return None;
    }
    Some(stem.to_string())
}

/// Stable storage key for the per-project router-facts index.
///
/// Uses the file's **full filesystem path** (lossy-converted to UTF-8)
/// because the only goal of the storage key is uniqueness across files
/// in a single scan.  Collisions on shorter forms (file basename or
/// `<parent_dir>::__init__`) are common in real codebases — airflow
/// alone has 17 `routes/__init__.py` files spread across providers and
/// test trees, and any keying scheme that drops the path prefix would
/// have one such file silently overwrite another's `include_router`
/// edges, breaking the cross-file lift on whichever parent lost the
/// race.
///
/// The lookup side ([`crate::summary::GlobalSummaries::resolve_cross_file_router_deps`])
/// iterates every stored entry and matches child references by the
/// **last segment** ([`module_id_for_path`]) — so duplicate-basename
/// children still get every parent's deps accumulated, which is the
/// FastAPI-runtime-correct behavior.  Path-based storage keys plus
/// basename-based lookup keys is the right pairing.
pub fn module_id_for_storage(path: &Path) -> Option<String> {
    let s = path.to_string_lossy();
    if s.is_empty() {
        return None;
    }
    Some(s.into_owned())
}

/// Extract router-level deps + include_router edges from a Python AST.
/// Returns `None` for non-Python files; pass 1 callers must gate on the
/// file's language slug before invoking.  Empty facts (no routers and no
/// edges) still return `Some(Default::default())` so callers can record
/// an empty index entry without re-extracting.
pub fn extract_router_facts_for_python(tree: &Tree, bytes: &[u8]) -> PerFileRouterFacts {
    let mut facts = PerFileRouterFacts::default();
    let root = tree.root_node();
    collect_local_router_deps(root, bytes, &mut facts.local_router_deps);
    collect_include_router_edges(root, bytes, &mut facts.include_router_edges);
    facts
}

/// Walk the module root for top-level `<id> = <RouterCtor>(..., dependencies=[…])`
/// assignments, mirroring
/// [`crate::auth_analysis::extract::flask::collect_router_level_dependencies`].
/// Reimplemented here to avoid an inter-module Visibility tangle and
/// to keep this module self-contained — the router extractor is the
/// single source of truth at FlaskExtractor::extract time, this module
/// is a parallel collection path that runs in pass 1.
fn collect_local_router_deps(
    root: Node<'_>,
    bytes: &[u8],
    out: &mut HashMap<String, Vec<(CallSite, bool)>>,
) {
    for child in named_children(root) {
        let assign = match child.kind() {
            "expression_statement" => named_children(child).into_iter().next(),
            "assignment" => Some(child),
            _ => None,
        };
        let Some(assign) = assign else { continue };
        if assign.kind() != "assignment" {
            continue;
        }
        let Some(left) = assign.child_by_field_name("left") else {
            continue;
        };
        if left.kind() != "identifier" {
            continue;
        }
        let Some(right) = assign.child_by_field_name("right") else {
            continue;
        };
        if right.kind() != "call" {
            continue;
        }
        let Some(function) = right.child_by_field_name("function") else {
            continue;
        };
        let function_text = text(function, bytes);
        if !is_router_like_constructor(&function_text) {
            continue;
        }
        let Some(arguments) = right.child_by_field_name("arguments") else {
            continue;
        };
        let Some(deps_value) = keyword_argument_value(arguments, bytes, "dependencies") else {
            continue;
        };
        let mut deps = Vec::new();
        for element in named_children(deps_value) {
            if let Some(unwrapped) = unwrap_depends_call(element, bytes) {
                deps.push(unwrapped);
            }
        }
        if deps.is_empty() {
            continue;
        }
        let var_name = text(left, bytes).trim().to_string();
        if var_name.is_empty() {
            continue;
        }
        out.entry(var_name).or_insert(deps);
    }
}

/// Walk every call expression in the file looking for
/// `<parent>.include_router(<child_module>.<child_var>, ...)` shapes.
/// Records `(parent_var, child_module_id, child_var)` for each.  Skips
/// edges where the child reference is a bare identifier (no module
/// segment) — those would require Python import resolution to attach
/// to a specific file, beyond this single-hop basename matching.
fn collect_include_router_edges(root: Node<'_>, bytes: &[u8], out: &mut Vec<RouterIncludeEdge>) {
    walk_for_include_router(root, bytes, out);
}

fn walk_for_include_router(node: Node<'_>, bytes: &[u8], out: &mut Vec<RouterIncludeEdge>) {
    if node.kind() == "call"
        && let Some(edge) = parse_include_router_call(node, bytes)
    {
        out.push(edge);
    }
    for child in named_children(node) {
        walk_for_include_router(child, bytes, out);
    }
}

fn parse_include_router_call(node: Node<'_>, bytes: &[u8]) -> Option<RouterIncludeEdge> {
    let function = node.child_by_field_name("function")?;
    if function.kind() != "attribute" {
        return None;
    }
    let attr = function.child_by_field_name("attribute")?;
    if text(attr, bytes) != "include_router" {
        return None;
    }
    let object = function.child_by_field_name("object")?;
    let parent_var = match object.kind() {
        "identifier" => text(object, bytes).trim().to_string(),
        _ => return None,
    };
    if parent_var.is_empty() {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    // First positional arg (skip keyword_argument children).
    let first = named_children(arguments)
        .into_iter()
        .find(|child| child.kind() != "keyword_argument")?;
    if first.kind() != "attribute" {
        return None;
    }
    let child_attr = first.child_by_field_name("attribute")?;
    let child_var = text(child_attr, bytes).trim().to_string();
    if child_var.is_empty() {
        return None;
    }
    let child_object = first.child_by_field_name("object")?;
    // Use the **last segment** of a possibly-dotted module reference as
    // the cross-file module id.  `task_instances.router` →
    // module_id="task_instances"; `pkg.task_instances.router` →
    // module_id="task_instances" (last attribute segment).
    let child_module_id = match child_object.kind() {
        "identifier" => text(child_object, bytes).trim().to_string(),
        "attribute" => {
            let inner_attr = child_object.child_by_field_name("attribute")?;
            text(inner_attr, bytes).trim().to_string()
        }
        _ => return None,
    };
    if child_module_id.is_empty() {
        return None;
    }
    Some(RouterIncludeEdge {
        parent_var,
        child_module_id,
        child_var,
    })
}

fn keyword_argument_value<'tree>(
    arguments: Node<'tree>,
    bytes: &[u8],
    name: &str,
) -> Option<Node<'tree>> {
    for arg in named_children(arguments) {
        if arg.kind() != "keyword_argument" {
            continue;
        }
        let key = arg.child_by_field_name("name")?;
        if text(key, bytes) == name {
            return arg.child_by_field_name("value");
        }
    }
    None
}

/// Local copy of the router-constructor recogniser (parallel to
/// [`crate::auth_analysis::extract::flask::is_router_like_constructor`]
/// to avoid the visibility tangle).
fn is_router_like_constructor(callee: &str) -> bool {
    let trimmed = callee.trim();
    let tail = trimmed.rsplit('.').next().unwrap_or(trimmed);
    if tail == "APIRouter" || tail == "FastAPI" || tail == "VersionedAPIRouter" {
        return true;
    }
    if tail.len() > "Router".len()
        && tail.ends_with("Router")
        && tail.chars().next().is_some_and(|c| c.is_ascii_uppercase())
    {
        return true;
    }
    false
}

/// Cross-file dep-marker unwrapper.  Differs from the in-file
/// [`crate::auth_analysis::extract::flask::unwrap_depends_call`] in
/// the *scoped-security* gating policy:
///
/// * **In-file** (per-route or per-router declarations visible to
///   the active file's FlaskExtractor): only `Security(callable,
///   scopes=[non-empty])` flips `scoped_security = true`.  A bare
///   `Security(callable)` stays as a LoginGuard — conservative because
///   per-route bare Security is often used for login-only deps.
///
/// * **Cross-file via `include_router`** (this function, persisted
///   into the project-wide router-facts index for the cross-file lift):
///   ANY `Security(...)` marker at the parent-router level flips
///   `scoped_security = true`, regardless of explicit `scopes=[...]`.
///   Rationale: the FastAPI architectural pattern
///   `parent_router = APIRouter(dependencies=[Security(callable)])`
///   followed by `parent_router.include_router(child_router, ...)` is
///   structurally a declaration that **every route under the child
///   router is auth-protected**.  Treating it as authorization (Other
///   AuthCheckKind, via the existing `inject_middleware_auth` scoped
///   promotion) is semantically correct — the developer's `Security`
///   marker placement IS the authorization signal.  Bare `Depends(...)`
///   at the parent-router level is NOT promoted (it's a generic dep,
///   often a login fetcher).
fn unwrap_depends_call(node: Node<'_>, bytes: &[u8]) -> Option<(CallSite, bool)> {
    if node.kind() != "call" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    let function_text = text(function, bytes);
    if !is_dep_marker_callee(&function_text) {
        return None;
    }
    let is_security = is_security_marker(&function_text);
    let arguments = node.child_by_field_name("arguments")?;
    let children = named_children(arguments);
    let first = children
        .iter()
        .copied()
        .find(|child| child.kind() != "keyword_argument")?;
    // Cross-file scoped policy: any Security marker at parent-router
    // level → scoped=true.  See doc comment above for rationale.
    let scoped_security = is_security;
    let _ = string_literal_value;
    let _ = keyword_argument_value;
    match first.kind() {
        "call" => Some((call_site_from_node(first, bytes), scoped_security)),
        "identifier" | "attribute" | "scoped_identifier" => {
            Some((call_site_from_node(first, bytes), scoped_security))
        }
        _ => None,
    }
}

fn is_dep_marker_callee(callee: &str) -> bool {
    let trimmed = callee.trim();
    matches!(
        trimmed,
        "Depends"
            | "fastapi.Depends"
            | "fastapi.params.Depends"
            | "Security"
            | "fastapi.Security"
            | "fastapi.params.Security"
    )
}

fn is_security_marker(callee: &str) -> bool {
    let trimmed = callee.trim();
    matches!(
        trimmed,
        "Security" | "fastapi.Security" | "fastapi.params.Security"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_python(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .expect("python language");
        parser.parse(source, None).expect("parse")
    }

    #[test]
    fn module_id_for_path_strips_py_extension() {
        assert_eq!(
            module_id_for_path(Path::new("/x/y/task_instances.py")),
            Some("task_instances".into())
        );
        // `__init__` returns None — parent files are storage-only, not
        // lookup keys.
        assert_eq!(module_id_for_path(Path::new("/x/y/__init__.py")), None);
    }

    #[test]
    fn module_id_for_storage_uses_full_path_to_avoid_basename_collisions() {
        // Different `routes/__init__.py` files in different packages
        // must produce DIFFERENT keys — basename / parent-dir keying
        // would collide on real codebases (airflow alone has 17
        // `routes/__init__.py` files across its provider tree).
        let a = module_id_for_storage(Path::new(
            "/x/airflow-core/src/airflow/api_fastapi/execution_api/routes/__init__.py",
        ))
        .unwrap();
        let b = module_id_for_storage(Path::new(
            "/x/airflow-core/src/airflow/api_fastapi/core_api/routes/__init__.py",
        ))
        .unwrap();
        assert_ne!(a, b);
    }

    /// Canonical airflow shape — `routes/__init__.py` declares
    /// `authenticated_router = VersionedAPIRouter(dependencies=[Security(require_auth)])`
    /// and lifts every per-file child router via `include_router(...)`.
    /// Pass 1 must capture both the parent's local deps and the edges
    /// targeting `task_instances.router`.  Cross-file Security wrappers
    /// (regardless of explicit `scopes=[...]`) are flagged scoped — the
    /// architectural intent of `parent_router = X(dependencies=[Security(callable)])
    /// + parent_router.include_router(child_router)` is auth scoping over
    /// every child route.  See the `unwrap_depends_call` doc comment for
    /// the policy rationale.
    #[test]
    fn extract_router_facts_captures_parent_and_edges() {
        let src = "from cadwyn import VersionedAPIRouter\n\
                   from fastapi import APIRouter, Security\n\
                   from . import task_instances, dag_runs\n\
                   from .security import require_auth\n\
                   \n\
                   execution_api_router = APIRouter()\n\
                   authenticated_router = VersionedAPIRouter(dependencies=[Security(require_auth)])\n\
                   \n\
                   authenticated_router.include_router(task_instances.router, prefix=\"/task-instances\")\n\
                   authenticated_router.include_router(dag_runs.router, prefix=\"/dag-runs\")\n\
                   execution_api_router.include_router(authenticated_router)\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let facts = extract_router_facts_for_python(&tree, bytes);

        let parent_deps = facts
            .local_router_deps
            .get("authenticated_router")
            .expect("authenticated_router deps captured");
        assert_eq!(parent_deps.len(), 1);
        let (site, scoped) = &parent_deps[0];
        assert_eq!(site.name, "require_auth");
        assert!(
            *scoped,
            "cross-file: any Security marker is scoped-equivalent"
        );

        // execution_api_router has no deps → no entry.
        assert!(
            facts
                .local_router_deps
                .get("execution_api_router")
                .is_none()
        );

        // Two child include_router edges + one nested
        // execution_api_router.include_router(authenticated_router) edge.
        assert!(facts.include_router_edges.iter().any(|e| {
            e.parent_var == "authenticated_router"
                && e.child_module_id == "task_instances"
                && e.child_var == "router"
        }));
        assert!(facts.include_router_edges.iter().any(|e| {
            e.parent_var == "authenticated_router"
                && e.child_module_id == "dag_runs"
                && e.child_var == "router"
        }));
    }

    /// `<parent>.include_router(<bare_var>)` — child reference is a bare
    /// identifier, no module segment.  Cannot resolve to a specific
    /// file, so no edge is emitted.  This includes the canonical
    /// `execution_api_router.include_router(authenticated_router)` chain
    /// where the child is a sibling router declared in the same file —
    /// transitive in-file lifts are handled by the local-deps map, not
    /// the cross-file edge list.
    #[test]
    fn extract_router_facts_skips_bare_identifier_child_refs() {
        let src = "outer = APIRouter()\nouter.include_router(authenticated_router)\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let facts = extract_router_facts_for_python(&tree, bytes);
        assert!(facts.include_router_edges.is_empty());
    }

    /// Scoped Security at the parent level (real-world airflow
    /// `ti_id_router` flavor).  The `scoped` flag must round-trip.
    #[test]
    fn extract_router_facts_picks_up_scoped_security() {
        let src = "ti_id_router = VersionedAPIRouter(\n    route_class=ExecutionAPIRoute,\n    dependencies=[\n        Security(require_auth, scopes=[\"ti:self\"]),\n    ],\n)\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let facts = extract_router_facts_for_python(&tree, bytes);
        let deps = facts
            .local_router_deps
            .get("ti_id_router")
            .expect("ti_id_router deps captured");
        let (_site, scoped) = &deps[0];
        assert!(*scoped, "scopes=[\"ti:self\"] must mark scoped");
    }

    /// Cross-file `Depends(callable)` at parent-router level is NOT
    /// scoped — the policy promotes only Security markers (which
    /// signal authorization intent), not generic Depends (which are
    /// often login fetchers).  Bare `Depends(get_current_user)` lifted
    /// onto a child router via `include_router` stays as a LoginGuard
    /// on the child's per-route auth checks.
    #[test]
    fn extract_router_facts_does_not_promote_depends() {
        let src = "from fastapi import APIRouter, Depends\n\
                   v1 = APIRouter(dependencies=[Depends(get_current_user)])\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let facts = extract_router_facts_for_python(&tree, bytes);
        let deps = facts.local_router_deps.get("v1").expect("v1 deps captured");
        let (_site, scoped) = &deps[0];
        assert!(!*scoped, "Depends never scoped-security at cross-file lift");
    }
}
