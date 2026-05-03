use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    Express,
    Koa,
    Fastify,
    Gin,
    Echo,
    Flask,
    Django,
    Spring,
    Rails,
    Sinatra,
    Axum,
    ActixWeb,
    Rocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    All,
    Use,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisUnitKind {
    RouteHandler,
    Function,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthCheckKind {
    LoginGuard,
    AdminGuard,
    Ownership,
    Membership,
    TokenExpiry,
    TokenRecipient,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Read,
    Mutation,
    TokenLookup,
}

/// Classification of a sensitive operation by the resource it targets.
/// `check_ownership_gaps` only fires on the first five classes ,
/// `InMemoryLocal` is never authorization-relevant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkClass {
    /// A write against a persistent datastore (SQL, ORM, or KV that
    /// crosses tenant boundaries).
    DbMutation,
    /// A read against a persistent datastore that may return rows
    /// belonging to another tenant without an explicit ownership check.
    DbCrossTenantRead,
    /// A publish / broadcast against a realtime bus (pub/sub, websocket
    /// channel, event stream).  Always auth-relevant because receivers
    /// are typically scoped by tenant id.
    RealtimePublish,
    /// An outbound HTTP / RPC call whose target or payload can encode a
    /// tenant-scoped identifier.
    OutboundNetwork,
    /// A cache read/write whose keys routinely cross tenant boundaries
    /// (Redis / memcache / distributed cache client).
    CacheCrossTenant,
    /// A method call against a local, in-memory collection (HashMap,
    /// HashSet, Vec, …), never authorization-relevant.
    InMemoryLocal,
}

impl SinkClass {
    /// Does this sink class participate in the missing-ownership gate?
    /// Only `InMemoryLocal` is excluded; all other classes are treated
    /// as potential cross-tenant sinks.
    pub fn is_auth_relevant(&self) -> bool {
        !matches!(self, SinkClass::InMemoryLocal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSourceKind {
    RequestParam,
    RequestBody,
    RequestQuery,
    Session,
    Identifier,
    MemberField,
    TokenField,
    ArrayIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueRef {
    pub source_kind: ValueSourceKind,
    pub name: String,
    pub base: Option<String>,
    pub field: Option<String>,
    pub index: Option<String>,
    pub span: (usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    pub name: String,
    pub args: Vec<String>,
    pub span: (usize, usize),
    /// Per-positional-argument value-refs.  Populated only by the
    /// structured `collect_call` path (the auxiliary
    /// `call_site_from_node` constructor leaves this empty); used to
    /// attribute synthesised helper-call auth checks to the concrete
    /// subjects passed by the caller.
    pub args_value_refs: Vec<Vec<ValueRef>>,
}

#[derive(Debug, Clone)]
pub struct AuthCheck {
    pub kind: AuthCheckKind,
    pub callee: String,
    pub subjects: Vec<ValueRef>,
    pub span: (usize, usize),
    pub line: usize,
    pub args: Vec<String>,
    pub condition_text: Option<String>,
    /// True when the check was declared at the route boundary
    /// (decorator / middleware / dependency-injection list) rather
    /// than as a per-call check inside the handler body.
    ///
    /// Route-level non-login-guard checks authorize the *entire*
    /// handler, they gate every value the handler receives, every
    /// row the handler fetches, and every operation downstream.  An
    /// in-body `auth_check_covers_subject` walk that requires a
    /// per-name subject match cannot model that semantics: a
    /// FastAPI `dependencies=[Depends(requires_access_dag(method=
    /// "POST", access_entity=DagAccessEntity.RUN))]` is opaque to
    /// the engine, the inner `requires_access_dag` call carries no
    /// per-arg subject ref pointing to `dag_id` or `dag.id`.  The
    /// flag tells `auth_check_covers_subject` to short-circuit
    /// `true` for any non-login-guard route-level check, leaving
    /// only the LoginGuard / TokenExpiry / TokenRecipient kinds
    /// (already excluded upstream by `has_prior_subject_auth`'s
    /// filter) to be ignored.
    ///
    /// Set by `inject_middleware_auth` (Django, Flask, FastAPI) at
    /// the route-decorator entry point.  Default `false` for
    /// in-body checks (`require_membership(user, group_id)`,
    /// `is_admin(user)`, etc.), those still flow through the
    /// per-subject coverage logic so a check on
    /// `community.creator_id` doesn't blanket-suppress every other
    /// subject in the unit.
    pub is_route_level: bool,
}

#[derive(Debug, Clone)]
pub struct SensitiveOperation {
    pub kind: OperationKind,
    /// Sink classification.  `None` means the operation was recorded
    /// for taxonomy completeness but does not match any known resource
    /// class, defensive, and currently unused.
    pub sink_class: Option<SinkClass>,
    pub callee: String,
    pub subjects: Vec<ValueRef>,
    pub span: (usize, usize),
    pub line: usize,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct AnalysisUnit {
    pub kind: AnalysisUnitKind,
    pub name: Option<String>,
    pub span: (usize, usize),
    pub params: Vec<String>,
    pub context_inputs: Vec<ValueRef>,
    pub call_sites: Vec<CallSite>,
    pub auth_checks: Vec<AuthCheck>,
    pub operations: Vec<SensitiveOperation>,
    pub value_refs: Vec<ValueRef>,
    pub condition_texts: Vec<String>,
    pub line: usize,
    /// Map from local variable name to the row binding it was read from.
    /// Populated when the extractor sees `let V = ROW.method(..)` or
    /// `let V = ROW.field`.  Used by `auth_check_covers_subject` so a
    /// row-level ownership-equality check on the row implicitly covers
    /// downstream uses of fields read from the same row.
    pub row_field_vars: HashMap<String, String>,
    /// Map from local variable name to the full member-chain expression
    /// it was bound from (`let community_id = req.community_id` →
    /// `community_id → "req.community_id"`).  Distinct from
    /// `row_field_vars`, which records only the receiver (loses the
    /// field name).  Powers the row-population reverse-walk's local-
    /// alias case: when a sink subject is a plain identifier, the
    /// reverse walk consults this map to also accept rows whose
    /// population args contain the aliased chain.
    pub var_alias_chain: HashMap<String, String>,
    /// Per row-binding metadata: the `let ROW = CALL(..)` declaration
    /// line and the value-refs appearing in the call's arguments.
    /// Populated for every `let V = call(..)` shape.  Powers the
    /// "fetch-then-authorize" exemption in `checks.rs`: if a row-fetch
    /// operation produces variable `V` and SOME auth check elsewhere
    /// in the unit names `V`, the row-fetch operation is considered
    /// authorized, even though the check appears textually after the
    /// fetch.  This is the standard idiom in row-level authz code:
    /// fetch the row first to extract the resource id, then call
    /// `check_<resource>_<role>(&user, &row, ...)` to authorize it.
    pub row_population_data: HashMap<String, (usize, Vec<ValueRef>)>,
    /// Variables bound to an authenticated-user value. Populated from
    /// `let V = require_auth(..).await?` (or any call matching the
    /// configured login-guard / authorization-check names) and from
    /// typed route-handler parameters (`CurrentUser`, `AuthUser`, …).
    /// Consulted by `is_actor_context_subject` so `V.id`-shaped subjects
    /// are treated as the caller's own id, not as a scoped foreign id.
    pub self_actor_vars: HashSet<String>,
    /// Variables holding the authenticated actor's identifier (transitive
    /// copies of `V.id` / `V.user_id` / `V.uid` / `V.userId` for some
    /// `V ∈ self_actor_vars`).  Populated when the extractor sees
    /// `let X = V.id` or `let X = (V.id as ..).into()` / `V.id.into()`
    /// shapes, anywhere a route-handler reduces the authenticated
    /// principal to a scalar id and reuses it as a SQL parameter.
    /// Consulted by `is_actor_context_subject` so subjects whose `name`
    /// is in this set count as actor context, not foreign scoped IDs.
    pub self_actor_id_vars: HashSet<String>,
    /// Local variables bound (directly or transitively) to a SQL query
    /// whose literal text classifies as authorization-gated by
    /// `sql_semantics::classify_sql_query`. Includes:
    ///   * the `let X = db.prepare(LIT)…` result var,
    ///   * the loop var of `for ROW in X`,
    ///   * column-binding vars `let Y = ROW.get(..)` whose receiver is
    ///     itself in this set.
    ///
    /// `auth_check_covers_subject` walks `row_field_vars` transitively
    /// and treats a subject as covered when the chain terminates in
    /// one of these names.
    pub authorized_sql_vars: HashSet<String>,
    /// Local variables bound (by `let`, `:=`, `var`, `const`) to a
    /// pure literal, string, integer, float, or boolean.  These are
    /// developer-chosen constants and cannot be user-controlled, so
    /// they must never trip `<lang>.auth.missing_ownership_check`
    /// even when the variable name passes `is_id_like`.  Closes the
    /// gin/context_test.go FP where `id := "id"` triggered the rule.
    pub const_bound_vars: HashSet<String>,
    /// Function parameter names whose static type maps to a
    /// payload-incompatible scalar ([`crate::ssa::type_facts::TypeKind::Int`]
    /// or [`crate::ssa::type_facts::TypeKind::Bool`]).  Populated
    /// per-file by `apply_typed_bounded_params` using the
    /// SSA-derived `VarTypes` map.  Consulted by
    /// `is_typed_bounded_subject` so parameters like Spring `Long
    /// userId`, Axum `Path<i64>`, or FastAPI `user_id: int` are not
    /// classified as scoped-identifier subjects even when their name
    /// passes `is_id_like`, the framework guarantees the value is a
    /// number that cannot carry a SQL/file/shell payload.
    pub typed_bounded_vars: HashSet<String>,
    /// per-DTO-extractor parameter, the field names whose
    /// declared type is a payload-incompatible scalar.  Map key is the
    /// parameter name (e.g. `dto`), value is the list of field names
    /// (e.g. `["age", "count"]`).  Populated by
    /// `apply_typed_bounded_params` only when the parameter
    /// itself was recognised as a typed extractor, bare parameters
    /// with no framework gate never lift their fields.
    pub typed_bounded_dto_fields: HashMap<String, Vec<String>>,
    /// Per-unit dynamic session-base text set, supplementing the
    /// hard-coded list in `is_self_scoped_session_base`.  Populated by
    /// the extractor when a parameter's static type signals a known
    /// auth-context shape, e.g. TRPC's `Options { ctx: { user:
    /// NonNullable<TrpcSessionUser> } }` adds `<localCtx>.user` so
    /// downstream `ctx.user.id` accesses count as actor context.  Each
    /// entry is the dotted base text (e.g. `"ctx.user"`,
    /// `"opts.ctx.user"`) that should match a subject's `base` when
    /// the subject's `field` is an id-like field name.  Distinct from
    /// `self_actor_vars` (single-segment locals) because TRPC
    /// destructures route through a base chain, not a top-level
    /// binding.
    pub self_scoped_session_bases: HashSet<String>,
}

/// Per-function summary of which positional parameters are
/// auth-checked inside the function body.  When a caller invokes this
/// function with `subject` at position K, and the summary says param
/// K has an auth check of kind `kind`, the caller's subject is
/// considered covered as if it were checked at the call site.
///
/// Serialises as a `Vec<(usize, AuthCheckKind)>` so same-shape on-disk
/// rows survive across HashMap iteration-order changes; the in-memory
/// type stays a HashMap for point-lookup efficiency.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthCheckSummary {
    #[serde(
        serialize_with = "serialize_param_auth_kinds",
        deserialize_with = "deserialize_param_auth_kinds"
    )]
    pub param_auth_kinds: HashMap<usize, AuthCheckKind>,
}

fn serialize_param_auth_kinds<S>(
    map: &HashMap<usize, AuthCheckKind>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut entries: Vec<(usize, AuthCheckKind)> =
        map.iter().map(|(idx, kind)| (*idx, *kind)).collect();
    entries.sort_by_key(|(idx, _)| *idx);
    let mut seq = serializer.serialize_seq(Some(entries.len()))?;
    for entry in entries {
        seq.serialize_element(&entry)?;
    }
    seq.end()
}

fn deserialize_param_auth_kinds<'de, D>(
    deserializer: D,
) -> Result<HashMap<usize, AuthCheckKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let entries: Vec<(usize, AuthCheckKind)> = Vec::deserialize(deserializer)?;
    Ok(entries.into_iter().collect())
}

#[derive(Debug, Clone)]
pub struct RouteRegistration {
    pub framework: Framework,
    pub method: HttpMethod,
    pub path: String,
    pub middleware: Vec<String>,
    pub handler_span: (usize, usize),
    pub handler_params: Vec<String>,
    pub file: PathBuf,
    pub line: usize,
    pub unit_idx: usize,
    pub middleware_calls: Vec<CallSite>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizationModel {
    pub routes: Vec<RouteRegistration>,
    pub units: Vec<AnalysisUnit>,
    /// Per-language web-framework presence signal used to gate the
    /// `is_external_input_param_name` arm of `unit_has_user_input_evidence`.
    ///
    /// `None` means detection did not run (single-file unit-test paths,
    /// languages without a framework gate yet).  `Some(true)` means the
    /// project manifest or the file's imports name a web framework that
    /// matches this language ─ helper functions are plausibly reachable
    /// from a route handler, so the param-name heuristic stays on.
    /// `Some(false)` means detection ran and named no matching framework
    /// ─ the file lives in a project with no HTTP boundary, so internal
    /// helper params named `*_id` / `req` / `payload` are not user input.
    ///
    /// Currently set only for Rust by `extract_authorization_model`.
    pub lang_web_framework_signal: Option<bool>,
    /// Source language of the file the model was built from.  Used by
    /// `unit_has_user_input_evidence` to apply per-language narrowing
    /// of the framework-request-name allow-list.  Empty string when no
    /// language was supplied (single-file unit-test paths).
    pub lang: String,
}

impl AuthorizationModel {
    pub fn extend(&mut self, other: AuthorizationModel) {
        let unit_offset = self.units.len();
        self.units.extend(other.units);
        self.routes
            .extend(other.routes.into_iter().map(|mut route| {
                route.unit_idx += unit_offset;
                route
            }));
        // Take the strongest signal across extractor outputs: `Some(true)`
        // wins over `Some(false)` wins over `None`.  In practice every
        // extractor for a given file sees the same `framework_ctx + bytes`
        // so they all derive identical signals; this is just a defensive
        // merge.
        self.lang_web_framework_signal = max_signal(
            self.lang_web_framework_signal,
            other.lang_web_framework_signal,
        );
    }
}

fn max_signal(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) | (_, Some(false)) => Some(false),
        _ => None,
    }
}
