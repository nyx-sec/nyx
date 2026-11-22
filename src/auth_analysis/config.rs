//! Configuration for the Rust auth-analysis pass.
//!
//! Holds [`AuthAnalysisRules`] (admin path/guard patterns, sink classes, and
//! name canonicalization) that drive `rs.auth.missing_ownership_check`.

use crate::auth_analysis::model::SinkClass;
use crate::labels::bare_method_name;
use crate::utils::config::Config;

#[derive(Debug, Clone)]
pub struct AuthAnalysisRules {
    pub enabled: bool,
    pub finding_prefix: String,
    pub admin_path_patterns: Vec<String>,
    pub admin_guard_names: Vec<String>,
    pub login_guard_names: Vec<String>,
    /// Typed-extractor wrapper names that carry route-level
    /// authorization (capability/policy enforcement) rather than mere
    /// authentication.  Match by `matches_name` (last-segment +
    /// case-insensitive `starts_with`), so a single pattern like
    /// `"Guarded"` covers `Guarded`, `GuardedData`, `GuardedRoute`.
    /// Consulted only by `inject_guard_checks` for typed-extractor
    /// route-level injection — distinct from `login_guard_names` /
    /// `admin_guard_names` so the pattern doesn't pollute regular call
    /// recognition (where a function like `guarded_load(..)` would
    /// otherwise be wrongly classified as a login guard).
    pub policy_guard_names: Vec<String>,
    pub authorization_check_names: Vec<String>,
    pub mutation_indicator_names: Vec<String>,
    pub read_indicator_names: Vec<String>,
    pub token_lookup_names: Vec<String>,
    pub token_expiry_fields: Vec<String>,
    pub token_recipient_fields: Vec<String>,
    pub non_sink_receiver_types: Vec<String>,
    pub non_sink_receiver_name_prefixes: Vec<String>,
    /// Built-in / framework receivers whose first-segment, when matched
    /// exactly (case-sensitive), classifies the call as inherently
    /// non-data-layer.  Used for browser/DOM globals (`document`,
    /// `window`, `localStorage`, `console`, ...) and stdlib helpers
    /// (`Math`, `JSON`, `Date`) where method names like `getById` /
    /// `addEventListener` would otherwise prefix-match the configured
    /// `read_indicator_names` / `mutation_indicator_names`.
    pub non_sink_global_receivers: Vec<String>,
    /// Method-name allowlist: when the LAST segment of a callee matches
    /// (case-sensitive exact), the call is classified as non-sink
    /// regardless of receiver.  Used for DOM-API methods
    /// (`addEventListener`, `getElementById`, `appendChild`, ...) that
    /// are categorically client-side and never authorization-relevant.
    pub non_sink_method_names: Vec<String>,
    /// Receiver-chain first-segment prefixes that classify a call as a
    /// realtime publish (pub/sub, websocket, event stream).
    pub realtime_receiver_prefixes: Vec<String>,
    /// Receiver-chain prefixes that classify a call as an outbound
    /// network sink (HTTP client, RPC caller).
    pub outbound_network_receiver_prefixes: Vec<String>,
    /// Receiver-chain prefixes that classify a call as a cross-tenant
    /// cache access.
    pub cache_receiver_prefixes: Vec<String>,
    /// ACL tables that, when JOIN-ed in a SELECT and pinned via
    /// `WHERE <ACL>.user_id = ?N`, make every returned row
    /// membership-gated.  See `sql_semantics::classify_sql_query`.
    pub acl_tables: Vec<String>,
    /// Callee names that, when they appear as the chain root of a
    /// chained-call shape (`select(X).filter_by(...)`,
    /// `query(X).filter(...)`), anchor the trailing method as a DB
    /// query-builder operation.  Overrides the chained-call suppression
    /// in `classify_sink_class` for SQLAlchemy / similar query-builder
    /// idioms whose first call returns an opaque builder object.
    pub db_query_builder_roots: Vec<String>,
    /// Receiver-chain segments that confine a lookup to the rows the caller
    /// may see (`Issue.visible.find(id)`, Redmine's `visible(user)` scope).
    /// `accessible_by` and `policy_scope` are always scopes, in every
    /// language; this list adds the framework-specific spellings.
    pub authorization_scope_segments: Vec<String>,
    /// Scope methods that confine rows only when the caller is passed to
    /// them: `Model.objects.visible_to_user(requestor)`.  A call with another
    /// argument (a channel, a slug) is not a scope on its own.
    pub actor_scope_segments: Vec<String>,
}

impl AuthAnalysisRules {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            finding_prefix: "auth".into(),
            admin_path_patterns: Vec::new(),
            admin_guard_names: Vec::new(),
            login_guard_names: Vec::new(),
            policy_guard_names: Vec::new(),
            authorization_check_names: Vec::new(),
            mutation_indicator_names: Vec::new(),
            read_indicator_names: Vec::new(),
            token_lookup_names: Vec::new(),
            token_expiry_fields: Vec::new(),
            token_recipient_fields: Vec::new(),
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            non_sink_global_receivers: Vec::new(),
            non_sink_method_names: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
            db_query_builder_roots: Vec::new(),
            authorization_scope_segments: Vec::new(),
            actor_scope_segments: Vec::new(),
        }
    }

    /// True for the JavaScript / TypeScript auth family (finding prefix
    /// `js.auth`).  JS/TS are the only supported auth languages whose
    /// tree-sitter grammar produces `object` / `object_expression` literal
    /// nodes.  Per-unit / per-file sub-analyses that scan for object-literal
    /// shapes (the NextAuth options-factory recogniser) are guaranteed to
    /// find nothing on Python/Ruby/Go/Java/Rust — those grammars spell object
    /// literals as `dictionary` / `hash` / `composite_literal` /
    /// `struct_expression`.  Gating such a scan on this predicate skips a
    /// fruitless whole-subtree walk without changing output (the scan would
    /// have returned `false` after walking anyway).
    #[inline]
    pub fn is_object_literal_lang(&self) -> bool {
        self.finding_prefix == "js.auth"
    }

    /// True for the Go auth family (finding prefix `go.auth`).
    #[inline]
    pub fn is_go_lang(&self) -> bool {
        self.finding_prefix == "go.auth"
    }

    /// True for the Python auth family (finding prefix `py.auth`).
    #[inline]
    pub fn is_python_lang(&self) -> bool {
        self.finding_prefix == "py.auth"
    }

    /// True for the Rust auth family (finding prefix `rs.auth`).
    #[inline]
    pub fn is_rust_lang(&self) -> bool {
        self.finding_prefix == "rs.auth"
    }

    /// Last path segment of a type name (e.g. `std::collections::HashMap` → `HashMap`).
    /// Accepts either `::` or `.` as the path separator.
    fn type_last_segment(ty: &str) -> &str {
        let trimmed = ty
            .trim()
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .trim();
        let after_colons = trimmed.rsplit("::").next().unwrap_or(trimmed);
        after_colons.rsplit('.').next().unwrap_or(after_colons)
    }

    /// Does `ty` (last path segment, case-sensitive) match a
    /// non-sink receiver type?  Generic suffixes are stripped first:
    /// `HashMap<i64, String>` → `HashMap` (Rust/Java/TS angle brackets),
    /// `set[int]` / `dict[str, int]` → `set` / `dict` (Python PEP 585
    /// builtin generics + `typing` aliases).
    pub fn is_non_sink_receiver_type(&self, ty: &str) -> bool {
        let base = Self::type_last_segment(ty);
        let base = base.split(['<', '[']).next().unwrap_or(base).trim();
        self.non_sink_receiver_types
            .iter()
            .any(|allowed| allowed == base)
    }

    /// Does the callee of a constructor expression (e.g. `HashMap::new`,
    /// `SmallVec::from`, `Vec::with_capacity`) produce a non-sink
    /// receiver?  Matches when the type prefix is in
    /// `non_sink_receiver_types` AND the method is a known
    /// constructor verb.
    ///
    /// The callee string may use either `::` or `.` as the path
    /// separator (nyx's `callee_name` normalizes both via
    /// `member_chain`).
    ///
    /// Bare-callee form: Python uses `set()` / `dict()` / `list()` /
    /// `defaultdict()` / etc. as direct constructors with no method
    /// segment.  When `callee` has no `.` / `::` separator and matches
    /// a registered non-sink receiver type, treat the call as a
    /// non-sink constructor.  Closes the
    /// `verified_ids = set(); verified_ids.update(myteams)` shape in
    /// sentry where the bare-call form was unrecognised so the bound
    /// var was missing from `non_sink_vars` and the later
    /// `.update(..)` classified as DbMutation.
    pub fn is_non_sink_constructor_callee(&self, callee: &str) -> bool {
        let normalized = callee.replace("::", ".");
        if let Some((ty, method)) = normalized.rsplit_once('.') {
            if !self.is_non_sink_receiver_type(ty) {
                return false;
            }
            return matches!(
                method,
                "new"
                    | "with_capacity"
                    | "with_capacity_and_hasher"
                    | "with_hasher"
                    | "from"
                    | "from_iter"
                    | "new_in"
                    | "default"
            );
        }
        self.is_non_sink_receiver_type(&normalized)
    }

    /// Does the first segment of a callee receiver chain look like a
    /// non-sink local variable, based on configured name prefixes?
    /// Used as a fallback when the type/binding cannot be resolved.
    pub fn receiver_matches_non_sink_prefix(&self, first_segment: &str) -> bool {
        if first_segment.is_empty() {
            return false;
        }
        self.non_sink_receiver_name_prefixes
            .iter()
            .any(|prefix| !prefix.is_empty() && first_segment.starts_with(prefix.as_str()))
    }

    /// Should a call on `callee` be skipped for Read/Mutation
    /// classification because its receiver is a local non-sink
    /// collection?  The `non_sink_vars` set lists variable names
    /// flagged during the unit walk (e.g. `let mut counts = HashMap::new()`).
    pub fn callee_has_non_sink_receiver(
        &self,
        callee: &str,
        non_sink_vars: &std::collections::HashSet<String>,
    ) -> bool {
        let first = first_receiver_segment(callee);
        if first.is_empty() {
            return false;
        }
        if non_sink_vars.contains(first) {
            return true;
        }
        self.receiver_matches_non_sink_prefix(first)
    }

    /// Does the first receiver-chain segment match a configured
    /// non-sink global (case-sensitive exact)?  Used to recognise
    /// browser/DOM globals (`document.getElementById` →
    /// first-segment `document`) and stdlib helpers
    /// (`Math.random`, `JSON.stringify`).
    pub fn callee_has_non_sink_global_receiver(&self, callee: &str) -> bool {
        let first = first_receiver_segment(callee);
        if first.is_empty() {
            return false;
        }
        self.non_sink_global_receivers
            .iter()
            .any(|name| name == first)
    }

    /// Does the LAST segment of the callee match a configured non-sink
    /// method name (case-sensitive exact)?  Used to recognise DOM-API
    /// methods like `addEventListener` / `appendChild` regardless of
    /// receiver, `someElement.addEventListener` is just as
    /// categorically client-side as `document.addEventListener`.
    pub fn callee_has_non_sink_method(&self, callee: &str) -> bool {
        let last = bare_method_name(callee);
        let last = last.rsplit("::").next().unwrap_or(last);
        if last.is_empty() {
            return false;
        }
        self.non_sink_method_names.iter().any(|name| name == last)
    }

    /// Does the first segment of the callee's receiver chain match any
    /// configured prefix in `prefixes`?  Comparison is case-insensitive
    /// on the first segment and uses starts-with on each prefix.
    fn receiver_matches_any_prefix(&self, first_segment: &str, prefixes: &[String]) -> bool {
        if first_segment.is_empty() {
            return false;
        }
        let lower = first_segment.to_ascii_lowercase();
        prefixes.iter().any(|prefix| {
            !prefix.is_empty() && lower.starts_with(prefix.to_ascii_lowercase().as_str())
        })
    }

    /// Classify a call into a [`SinkClass`].
    ///
    /// Dispatch order (first match wins):
    ///   1. `InMemoryLocal`, receiver is a known non-sink collection
    ///      (tracked in `non_sink_vars` or matches a configured
    ///      non-sink prefix).
    ///   2. `RealtimePublish`, receiver first-segment matches a
    ///      configured realtime prefix (e.g. `realtime`, `pubsub`).
    ///   3. `OutboundNetwork`, receiver first-segment matches a
    ///      configured outbound-network prefix (e.g. `http`, `reqwest`).
    ///   4. `CacheCrossTenant`, receiver first-segment matches a
    ///      configured cache prefix (e.g. `cache`, `redis`).
    ///   5. `DbMutation`, callee name matches `mutation_indicator_names`.
    ///   6. `DbCrossTenantRead`, callee name matches `read_indicator_names`.
    ///
    /// Returns `None` when the callee matches none of the above, the
    /// call site is ignored by ownership-gap checks.
    pub fn classify_sink_class(
        &self,
        callee: &str,
        non_sink_vars: &std::collections::HashSet<String>,
    ) -> Option<SinkClass> {
        self.classify_sink_class_with_models(
            callee,
            non_sink_vars,
            &std::collections::HashSet::new(),
        )
    }

    /// [`Self::classify_sink_class`] with the file's ORM model classes
    /// (Python), so a bare `Model.get(..)` on one is a row read.
    pub fn classify_sink_class_with_models(
        &self,
        callee: &str,
        non_sink_vars: &std::collections::HashSet<String>,
        orm_models: &std::collections::HashSet<String>,
    ) -> Option<SinkClass> {
        if self.callee_has_non_sink_receiver(callee, non_sink_vars) {
            return Some(SinkClass::InMemoryLocal);
        }
        // Browser/DOM globals (`document.getElementById`, `window.scrollTo`,
        // `Math.random`, `JSON.parse`) and DOM-API methods on any receiver
        // (`el.addEventListener`, `parent.appendChild`) are categorically
        // not data-layer auth-relevant operations.  These shapes would
        // otherwise prefix-match read/mutation indicators (`get`, `add`,
        // `remove`), `getElementById` canonicalises to `getelementbyid`
        // which `starts_with("get")`, and falsely classify as
        // `DbCrossTenantRead` / `DbMutation`.
        if self.callee_has_non_sink_global_receiver(callee)
            || self.callee_has_non_sink_method(callee)
        {
            return Some(SinkClass::InMemoryLocal);
        }
        // Python `.get(..)` is mostly a dictionary lookup (`options.get(key)`,
        // `cache.get(k)`, `request.GET.get("id")`) and `.get_*(..)` an ordinary
        // method (`group.get_absolute_url`).  Both are reads of rows only on an
        // ORM receiver (`Model.objects.get`, `db.session.get`).
        if self.is_python_lang() && is_non_orm_get(callee, orm_models) {
            return None;
        }
        // An id, or a collection of ids, is a value and never a data-layer
        // client: `uniqueIDs.Remove(0)`, `r.configVersionID.Load()`.
        if receiver_is_id_value(callee) {
            return Some(SinkClass::InMemoryLocal);
        }
        // Go request data: `r.Header.Add(..)`, `r.Form.Get(..)`.  Header maps,
        // form values and URLs are read off the request, not a store.
        if self.is_go_lang() && receiver_passes_through_request_data(callee) {
            return Some(SinkClass::InMemoryLocal);
        }
        let first = first_receiver_segment(callee);
        if self.receiver_matches_any_prefix(first, &self.realtime_receiver_prefixes) {
            return Some(SinkClass::RealtimePublish);
        }
        if self.receiver_matches_any_prefix(first, &self.outbound_network_receiver_prefixes) {
            return Some(SinkClass::OutboundNetwork);
        }
        if self.receiver_matches_any_prefix(first, &self.cache_receiver_prefixes) {
            return Some(SinkClass::CacheCrossTenant);
        }
        // Verb-name fallback (`is_mutation` / `is_read`) is the loosest
        // dispatch: it prefix-matches the bare method name against
        // generic verbs (`Get`, `Save`, `Find`, …) regardless of the
        // receiver.  Two structural shapes lack the receiver evidence
        // needed to anchor a DB-sink classification and are excluded:
        //
        //   1. Chained-call receiver (`w.Header().Get(..)`,
        //      `r.URL.Query().Get(..)`, `db.Tx(..).Query(..)`) — the
        //      receiver is the *return value of another call*, its type
        //      is opaque to the auth analyser.
        //   2. Bare-identifier callee with no receiver dot at all
        //      (`list(..)`, `filter(..)`, `create_audit_entry(..)`,
        //      `update_coding_agent_state(..)`) — Python / JS / Ruby
        //      builtins and locally-defined helpers routinely collide
        //      with the verb vocabulary.  Real ORM / DB calls always
        //      carry a receiver (`User.find(id)`, `Model.objects.filter`,
        //      `repo.save(x)`); a bare `list(events)` is the Python
        //      builtin and `filter(fn, xs)` is `Iterable.filter`.
        //
        // The realtime / outbound / cache prefix dispatches above
        // already match by the chain root; gating the verb fallback on
        // a simple non-chained receiver dot prevents both shapes from
        // masquerading as data-layer sinks while leaving canonical
        // `repo.Find(id)` / `db.Query(..)` calls unaffected.
        if receiver_is_simple_chain(callee) {
            if self.is_mutation(callee) {
                return Some(SinkClass::DbMutation);
            }
            if self.is_read(callee) {
                return Some(SinkClass::DbCrossTenantRead);
            }
        }
        // SQLAlchemy / query-builder chained shapes:
        // `select(X).filter_by(...)`, `query(X).filter(...)`,
        // `select().join().where()`.  The chain receiver is the return
        // value of an opaque builder primitive that the type tracker
        // cannot follow, but the chain *root* segment is itself a known
        // DB query-builder verb — strong enough evidence to anchor a
        // DB-sink classification when paired with a mutation/read verb
        // on the trailing method.  Closes airflow-style
        // `session.scalar(select(C).filter_by(conn_id=user_input))`.
        if receiver_is_chained_call(callee) && self.chain_root_is_db_query_builder(callee) {
            if self.is_mutation(callee) {
                return Some(SinkClass::DbMutation);
            }
            if self.is_read(callee) {
                return Some(SinkClass::DbCrossTenantRead);
            }
        }
        None
    }

    /// True when any non-final segment of the chain is an
    /// intermediate-call (ends with `()`) whose verb matches a
    /// configured `db_query_builder_roots` entry.  Used to anchor
    /// chained-call shapes like `select(X).filter_by(id=...)` (Python)
    /// or `query(X).filter(...)` to a DB-sink classification despite
    /// the opaque builder return value.
    pub fn chain_root_is_db_query_builder(&self, callee: &str) -> bool {
        if self.db_query_builder_roots.is_empty() {
            return false;
        }
        let segments: Vec<&str> = callee.split('.').collect();
        if segments.len() < 2 {
            return false;
        }
        for seg in &segments[..segments.len() - 1] {
            if !seg.ends_with(')') {
                continue;
            }
            let stripped = seg
                .trim_end_matches(')')
                .trim_end_matches('(')
                .trim_end_matches(')');
            if stripped.is_empty() {
                continue;
            }
            if self
                .db_query_builder_roots
                .iter()
                .any(|root| matches_name(stripped, root))
            {
                return true;
            }
        }
        false
    }

    pub fn requires_admin_path(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        let normalized = if lower.starts_with('/') {
            lower.clone()
        } else {
            format!("/{lower}")
        };
        self.admin_path_patterns
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .any(|p| normalized.contains(&p) || lower.contains(p.trim_matches('/')))
    }

    pub fn is_admin_guard(&self, name: &str, args: &[String]) -> bool {
        // Role lists and role-gating middleware admit a holder of ANY listed
        // role, so the guard is only as strong as its weakest role:
        // `hasAnyRole('ADMIN', 'USER')`, `@Secured({"ROLE_ADMIN",
        // "ROLE_USER"})` and `requireRoles('viewer')` are not admin guards.
        // This runs before `admin_guard_names` so a role gate whose name is
        // also listed there (`requireRole`) is still decided by its arguments.
        if matches_name(name, "hasAnyRole")
            || matches_name(name, "hasAnyAuthority")
            || matches_name(name, "PreAuthorize")
            || matches_name(name, "Secured")
            || matches_name(name, "RolesAllowed")
            || matches_name(name, "hasRole")
            || matches_name(name, "hasAuthority")
            || is_role_gate_name(name)
        {
            return every_role_is_privileged(args);
        }

        if self
            .admin_guard_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
        {
            return true;
        }

        if matches_name(name, "permission_required")
            || matches_name(name, "PermissionRequiredMixin")
            || matches_name(name, "user_passes_test")
        {
            return args.iter().any(|arg| {
                let lower = strip_quotes(arg).to_ascii_lowercase();
                lower.contains("admin")
                    || lower.contains("staff")
                    || lower.contains("manage")
                    || lower.contains("auth.")
                    || lower.contains("change_")
                    || lower.contains("delete_")
                    || lower.contains("add_")
            });
        }

        false
    }

    pub fn is_login_guard(&self, name: &str) -> bool {
        if matches_name(name, "isAuthenticated")
            || matches_name(name, "authenticated")
            || matches_name(name, "hasRole")
            || matches_name(name, "hasAnyRole")
            || matches_name(name, "hasAuthority")
            || matches_name(name, "hasAnyAuthority")
            || matches_name(name, "Secured")
            || matches_name(name, "RolesAllowed")
            || matches_name(name, "PreAuthorize")
        {
            return true;
        }

        self.login_guard_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    /// Typed-extractor wrapper that proves the request passed a
    /// route-level capability/policy check (e.g. meilisearch's
    /// `GuardedData<ActionPolicy<X>, _>`).  Distinct from
    /// `is_login_guard` because policy enforcement is more than mere
    /// authentication, it includes the per-action permission decision
    /// the Policy term encodes.  Used only by `inject_guard_checks`
    /// for typed-extractor route-level injection.
    pub fn is_policy_guard(&self, name: &str) -> bool {
        self.policy_guard_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    pub fn is_authorization_check(&self, name: &str) -> bool {
        if self
            .authorization_check_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
        {
            return true;
        }
        // Structural recogniser for the canonical Rust / cross-language
        // `require_<resource>_<role>` shape (`require_trip_member`,
        // `require_doc_owner`, `require_project_admin`).  The resource
        // segment is project-specific so cannot be enumerated in the
        // per-language defaults; the `<role>` suffix is a closed set of
        // authorization vocabulary.  This recogniser closes a real-repo
        // FP cluster where a project-named membership helper was
        // shadowing every realtime/db sink in the file.
        is_require_resource_role_call(name)
    }

    pub fn is_token_lookup(&self, name: &str) -> bool {
        self.token_lookup_names
            .iter()
            .any(|pattern| matches_qualified_name(name, pattern))
    }

    pub fn is_token_lookup_call(&self, name: &str, call_text: &str) -> bool {
        if self.is_token_lookup(name) {
            return true;
        }

        // Cheap name gate before the whole-call-text `to_ascii_lowercase`
        // allocation.  The substring fallback only matches read-shaped callees,
        // and this predicate is evaluated on *every* call node during auth
        // extraction, so lowercasing the entire call expression for calls whose
        // name can never qualify is pure waste.  `A && B == B && A` for bools,
        // so the reordered short-circuit is result-identical to the prior
        // `looks_like_token_query && read_shaped` form.
        let read_shaped = self.is_read(name)
            || matches_name(name, "get")
            || matches_name(name, "filter")
            || matches_name(name, "first")
            || matches_name(name, "one");
        if !read_shaped {
            return false;
        }

        let lower = call_text.to_ascii_lowercase();
        lower.contains("token=")
            || lower.contains("token =")
            || lower.contains("invite")
            || lower.contains("invitation")
            || lower.contains("accept_key")
    }

    pub fn is_mutation(&self, name: &str) -> bool {
        self.mutation_indicator_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    pub fn is_read(&self, name: &str) -> bool {
        self.read_indicator_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    pub fn has_expiry_field(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.token_expiry_fields
            .iter()
            .map(|field| field.to_ascii_lowercase())
            .any(|field| lower.contains(&field))
    }

    pub fn has_recipient_field(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.token_recipient_fields
            .iter()
            .map(|field| field.to_ascii_lowercase())
            .any(|field| lower.contains(&field))
    }

    pub fn rule_id(&self, suffix: &str) -> String {
        format!("{}.{}", self.finding_prefix, suffix)
    }
}

fn auth_finding_prefix(lang_slug: &str) -> Option<&'static str> {
    match lang_slug {
        "javascript" | "typescript" => Some("js.auth"),
        "python" => Some("py.auth"),
        "ruby" => Some("rb.auth"),
        "go" => Some("go.auth"),
        "java" => Some("java.auth"),
        "rust" => Some("rs.auth"),
        _ => None,
    }
}

fn auth_config_slugs(lang_slug: &str) -> &'static [&'static str] {
    match lang_slug {
        "typescript" => &["javascript", "typescript"],
        "javascript" => &["javascript"],
        "python" => &["python"],
        "ruby" => &["ruby"],
        "go" => &["go"],
        "java" => &["java"],
        "rust" => &["rust"],
        _ => &[],
    }
}

pub fn build_auth_rules(config: &Config, lang_slug: &str) -> AuthAnalysisRules {
    let Some(finding_prefix) = auth_finding_prefix(lang_slug) else {
        return AuthAnalysisRules::disabled();
    };

    let mut rules = if matches!(lang_slug, "python") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "admin_required".into(),
                "staff_member_required".into(),
                "is_admin".into(),
                "is_staff".into(),
                "permission_required".into(),
                "PermissionRequiredMixin".into(),
                "AdminRequiredMixin".into(),
            ],
            login_guard_names: vec![
                "login_required".into(),
                "LoginRequiredMixin".into(),
                "require_login".into(),
                "ensure_authenticated".into(),
                "require_auth".into(),
            ],
            policy_guard_names: Vec::new(),
            authorization_check_names: vec![
                "check_membership".into(),
                "has_membership".into(),
                "require_membership".into(),
                "ensure_membership".into(),
                "is_member".into(),
                "check_ownership".into(),
                "has_ownership".into(),
                "require_ownership".into(),
                "ensure_ownership".into(),
                "is_owner".into(),
                "owns_".into(),
                "permission_required".into(),
                "has_perm".into(),
                "has_permission".into(),
                "has_object_permission".into(),
                // DRF permission class that decides per object.
                // `DjangoModelPermissions` is not listed: it grants by model,
                // so a holder of `change_note` may change every row.
                "DjangoObjectPermissions".into(),
                "user_passes_test".into(),
                "verify_access".into(),
                "authorize".into(),
                // FastAPI dependency-injection auth idiom: airflow uses
                // `Depends(requires_access_dag(method="GET"))`,
                // `requires_access_connection(...)`, etc.  The unwrapped
                // inner call name is `requires_access_<resource>`; the
                // `requires_access` prefix matches all variants via
                // `matches_name`.
                "requires_access".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "delete".into(),
                "create".into(),
                "save".into(),
                "bulk_update".into(),
                "bulk_create".into(),
                "archive".into(),
                "publish".into(),
                "remove".into(),
                "add".into(),
                "confirm".into(),
                "invite".into(),
                "accept".into(),
            ],
            read_indicator_names: vec![
                "get".into(),
                "filter".into(),
                "find".into(),
                "fetch".into(),
                "load".into(),
                "list".into(),
                "retrieve".into(),
            ],
            token_lookup_names: vec![
                "find_by_token".into(),
                "lookup_by_token".into(),
                "get_by_token".into(),
                "get_invitation_by_token".into(),
                "Invitation.objects.get".into(),
                "invite_lookup".into(),
                "invitation_lookup".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiresat".into(),
                "expiry".into(),
                "expires".into(),
                "expired".into(),
                "has_expired".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientemail".into(),
                "invited_email".into(),
                "invitedemail".into(),
                "recipient".into(),
            ],
            // Python builtin / `collections` non-sink container types.
            // Recognised both as type-annotation hints (`x: set[int]`)
            // and as bare-callee constructor forms (`x = set()`,
            // `cache = collections.defaultdict(list)`, …).  Method
            // calls on bound vars (`x.update`, `x.add`, `cache.pop`)
            // are then classified as `InMemoryLocal`, suppressing the
            // false `DbMutation` / `DbCrossTenantRead` sink shape.
            // Closes sentry `api/helpers/teams.py:46` shape where
            // `verified_ids = set(); verified_ids.update(myteams)` was
            // flagged as cross-tenant mutation.
            non_sink_receiver_types: vec![
                "set".into(),
                "dict".into(),
                "list".into(),
                "tuple".into(),
                "frozenset".into(),
                "defaultdict".into(),
                "OrderedDict".into(),
                "Counter".into(),
                "deque".into(),
                "ChainMap".into(),
                "namedtuple".into(),
            ],
            non_sink_receiver_name_prefixes: Vec::new(),
            non_sink_global_receivers: Vec::new(),
            non_sink_method_names: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
            // SQLAlchemy queryset builders.  `select(X).filter_by(id=...)`
            // / `query(X).filter(id=...)` chains return opaque builder
            // objects whose type the auth analyser cannot follow; the
            // chain *root* primitive itself is the DB-anchor evidence.
            // Closes airflow-style `session.scalar(select(C).filter_by(...))`.
            db_query_builder_roots: vec!["select".into(), "query".into()],
            authorization_scope_segments: Vec::new(),
            actor_scope_segments: vec![
                "visible_to_user".into(),
                "visible_to".into(),
                "viewable_by".into(),
                "readable_by".into(),
            ],
        }
    } else if matches!(lang_slug, "ruby") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "require_admin".into(),
                "require_admin!".into(),
                "authenticate_admin".into(),
                "authenticate_admin!".into(),
                "ensure_admin".into(),
                "ensure_admin!".into(),
                "admin_only".into(),
                "admin_only!".into(),
                "admin_required".into(),
                "admin_required!".into(),
            ],
            login_guard_names: vec![
                "require_login".into(),
                "require_login!".into(),
                "authenticate_user".into(),
                "authenticate_user!".into(),
                "authenticate".into(),
                "authenticate!".into(),
                "ensure_authenticated".into(),
                "ensure_authenticated!".into(),
                "login_required".into(),
                "login_required!".into(),
            ],
            policy_guard_names: Vec::new(),
            authorization_check_names: vec![
                "authorize".into(),
                "authorize!".into(),
                // CanCanCan class macro: authorizes every action it covers.
                "load_and_authorize_resource".into(),
                "check_membership".into(),
                "check_membership!".into(),
                "has_membership".into(),
                "has_membership?".into(),
                "require_membership".into(),
                "require_membership!".into(),
                "ensure_membership".into(),
                "ensure_membership!".into(),
                "member_of?".into(),
                "member?".into(),
                "check_ownership".into(),
                "check_ownership!".into(),
                "has_ownership".into(),
                "has_ownership?".into(),
                "require_ownership".into(),
                "require_ownership!".into(),
                "ensure_ownership".into(),
                "ensure_ownership!".into(),
                "owner?".into(),
                "owns?".into(),
                "verify_access".into(),
                "verify_access!".into(),
                "can_access?".into(),
                "can?".into(),
                // Rails per-record permission predicates, the canonical
                // "load by id, then check on the loaded record" idiom
                // (see redmine `app/controllers/issues_controller.rb`,
                // mastodon controllers, diaspora ApplicationController).
                // Combined with `row_population_data` reverse-walk, this
                // recognises the post-fetch ownership check that is
                // textually after the find call.
                "visible?".into(),
                "editable?".into(),
                "editable_by?".into(),
                "deletable?".into(),
                "deletable_by?".into(),
                "destroyable?".into(),
                "destroyable_by?".into(),
                "commentable?".into(),
                "commentable_by?".into(),
                "permitted?".into(),
                "accessible?".into(),
                "accessible_by?".into(),
                "authorized?".into(),
                "allowed_to?".into(),
                "allowed?".into(),
                "viewable?".into(),
                "viewable_by?".into(),
                "writable?".into(),
                "writable_by?".into(),
                "readable?".into(),
                "readable_by?".into(),
                "manageable?".into(),
                "manageable_by?".into(),
                "owned_by?".into(),
                "belongs_to?".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "update!".into(),
                "delete".into(),
                "delete!".into(),
                "destroy".into(),
                "destroy!".into(),
                "create".into(),
                "create!".into(),
                "save".into(),
                "save!".into(),
                "archive".into(),
                "archive!".into(),
                "publish".into(),
                "publish!".into(),
                "remove".into(),
                "remove!".into(),
                "add".into(),
                "add!".into(),
                "confirm".into(),
                "confirm!".into(),
                "invite".into(),
                "invite!".into(),
                "accept".into(),
                "accept!".into(),
            ],
            read_indicator_names: vec![
                "find".into(),
                "find_by".into(),
                "find_by!".into(),
                "where".into(),
                "first".into(),
                "last".into(),
                "take".into(),
                "pluck".into(),
                "load".into(),
                "fetch".into(),
                "get".into(),
                "lookup".into(),
                "retrieve".into(),
            ],
            token_lookup_names: vec![
                "find_by_token".into(),
                "find_by_token!".into(),
                "find_by_invite_token".into(),
                "find_by_invite_token!".into(),
                "find_by_invitation_token".into(),
                "find_by_invitation_token!".into(),
                "find_by_accept_token".into(),
                "find_by_accept_token!".into(),
                "find_signed".into(),
                "find_signed!".into(),
                "lookup_invitation".into(),
                "lookup_invitation!".into(),
                "Invitation.find_by".into(),
                "Invitation.find_by!".into(),
                "Invite.find_by".into(),
                "Invite.find_by!".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiry".into(),
                "expires".into(),
                "expired".into(),
                "expired?".into(),
                "expired_at".into(),
                "valid_until".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipient".into(),
                "invited_email".into(),
                "invitee_email".into(),
                "user_email".into(),
            ],
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            non_sink_global_receivers: Vec::new(),
            non_sink_method_names: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
            db_query_builder_roots: Vec::new(),
            // Bare `visible` is not here: in most Rails apps it is a publish
            // flag scope, not an authorization scope.  `visible(current_user)`
            // counts through `actor_scope_segments`.
            authorization_scope_segments: vec!["viewable_by".into(), "readable_by".into()],
            actor_scope_segments: vec!["visible".into()],
        }
    } else if matches!(lang_slug, "go") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "RequireAdmin".into(),
                "AdminOnly".into(),
                "EnsureAdmin".into(),
                "requireAdmin".into(),
                "adminOnly".into(),
                "ensureAdmin".into(),
            ],
            login_guard_names: vec![
                "RequireLogin".into(),
                "RequireAuth".into(),
                "EnsureAuthenticated".into(),
                "AuthMiddleware".into(),
                "requireLogin".into(),
                "requireAuth".into(),
                "ensureAuthenticated".into(),
            ],
            policy_guard_names: Vec::new(),
            authorization_check_names: vec![
                "CheckMembership".into(),
                "HasMembership".into(),
                "RequireMembership".into(),
                "EnsureMembership".into(),
                "IsMember".into(),
                "CheckOwnership".into(),
                "HasOwnership".into(),
                "RequireOwnership".into(),
                "EnsureOwnership".into(),
                "IsOwner".into(),
                "Authorize".into(),
                "VerifyAccess".into(),
                "HasPermission".into(),
                "CanAccess".into(),
            ],
            mutation_indicator_names: vec![
                "Update".into(),
                "Delete".into(),
                "Create".into(),
                "Save".into(),
                "Archive".into(),
                "Publish".into(),
                "Remove".into(),
                "Add".into(),
                "Confirm".into(),
                "Invite".into(),
                "Accept".into(),
            ],
            read_indicator_names: vec![
                "Find".into(),
                "Get".into(),
                "List".into(),
                "Load".into(),
                "Fetch".into(),
                "Lookup".into(),
                "Query".into(),
            ],
            token_lookup_names: vec![
                "FindByToken".into(),
                "LookupByToken".into(),
                "FindInvitationByToken".into(),
                "FindInviteByToken".into(),
                "GetInvitationByToken".into(),
                "LookupInvitation".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiresat".into(),
                "expiresAt".into(),
                "expiry".into(),
                "expired".into(),
                "validUntil".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientEmail".into(),
                "invited_email".into(),
                "invitedEmail".into(),
                "invitee_email".into(),
                "inviteeEmail".into(),
                "recipient".into(),
            ],
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            // Standard-library packages whose functions work on values the
            // caller already holds (`slices.Delete`, `sort.Find`,
            // `maps.Keys`, `atomic.AddInt64`).  A call rooted at one of
            // these is never a data-layer operation.
            non_sink_global_receivers: [
                "slices", "maps", "sort", "strings", "bytes", "strconv", "atomic", "fmt", "math",
                "errors", "filepath", "path", "unicode", "utf8", "regexp", "base64", "hex",
                "binary", "bits", "cmp", "reflect", "big", "time",
            ]
            .iter()
            .map(|name| name.to_string())
            .collect(),
            non_sink_method_names: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
            db_query_builder_roots: Vec::new(),
            authorization_scope_segments: Vec::new(),
            actor_scope_segments: Vec::new(),
        }
    } else if matches!(lang_slug, "java") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "RequireAdmin".into(),
                "AdminOnly".into(),
                "EnsureAdmin".into(),
                "adminOnly".into(),
            ],
            login_guard_names: vec![
                "RequireLogin".into(),
                "LoginRequired".into(),
                "EnsureAuthenticated".into(),
                "Authenticated".into(),
                "isAuthenticated".into(),
            ],
            policy_guard_names: Vec::new(),
            authorization_check_names: vec![
                "checkMembership".into(),
                "hasMembership".into(),
                "requireMembership".into(),
                "ensureMembership".into(),
                "isMember".into(),
                "checkOwnership".into(),
                "hasOwnership".into(),
                "requireOwnership".into(),
                "ensureOwnership".into(),
                "isOwner".into(),
                "authorize".into(),
                "verifyAccess".into(),
                "hasPermission".into(),
                "canAccess".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "delete".into(),
                "create".into(),
                "save".into(),
                "archive".into(),
                "publish".into(),
                "remove".into(),
                "add".into(),
                "confirm".into(),
                "invite".into(),
                "accept".into(),
            ],
            read_indicator_names: vec![
                "find".into(),
                "get".into(),
                "load".into(),
                "fetch".into(),
                "lookup".into(),
                "read".into(),
                "query".into(),
            ],
            token_lookup_names: vec![
                "findByToken".into(),
                "findByInviteToken".into(),
                "findByInvitationToken".into(),
                "findByAcceptToken".into(),
                "getByToken".into(),
                "lookupByToken".into(),
                "lookupInvitation".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiresAt".into(),
                "expiry".into(),
                "expired".into(),
                "validUntil".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientEmail".into(),
                "invited_email".into(),
                "invitedEmail".into(),
                "invitee_email".into(),
                "inviteeEmail".into(),
                "recipient".into(),
            ],
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            non_sink_global_receivers: Vec::new(),
            non_sink_method_names: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
            db_query_builder_roots: Vec::new(),
            authorization_scope_segments: Vec::new(),
            actor_scope_segments: Vec::new(),
        }
    } else if matches!(lang_slug, "rust") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "require_admin".into(),
                "ensure_admin".into(),
                "admin_only".into(),
                "admin_guard".into(),
                "AdminUser".into(),
                "AdminGuard".into(),
                "RequireAdmin".into(),
            ],
            login_guard_names: vec![
                "require_login".into(),
                "require_auth".into(),
                "ensure_authenticated".into(),
                "authenticated".into(),
                "CurrentUser".into(),
                "SessionUser".into(),
                "AuthUser".into(),
                "RequireLogin".into(),
                "RequireAuth".into(),
            ],
            // `Guarded` (case-insensitive starts_with) recognises
            // typed-extractor wrappers like meilisearch's
            // `GuardedData<ActionPolicy<{ actions::KEYS_GET }>, _>` as
            // route-level policy guards (capability enforcement).  The
            // wrapper proves the request passed a permission check, so
            // any sink in the handler is route-gated even when the
            // engine cannot model the inner Policy term.
            policy_guard_names: vec!["Guarded".into()],
            authorization_check_names: vec![
                "check_membership".into(),
                "has_membership".into(),
                "require_membership".into(),
                "ensure_membership".into(),
                "is_member".into(),
                "check_ownership".into(),
                "has_ownership".into(),
                "require_ownership".into(),
                "ensure_ownership".into(),
                "is_owner".into(),
                "authorize".into(),
                "verify_access".into(),
                "has_permission".into(),
                "can_access".into(),
                "can_manage".into(),
                // Common project-specific helpers seen in real Axum/Rocket
                // codebases, kept as defaults so user code that names
                // its membership helper after the resource still gets
                // recognised.  Users can extend via `nyx.toml`.
                "require_group_member".into(),
                "require_org_member".into(),
                "require_workspace_member".into(),
                "require_tenant_member".into(),
                "require_team_member".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "delete".into(),
                "destroy".into(),
                "create".into(),
                "save".into(),
                "archive".into(),
                "publish".into(),
                "remove".into(),
                "insert".into(),
                "add".into(),
                "confirm".into(),
                "invite".into(),
                "accept".into(),
                "set".into(),
            ],
            read_indicator_names: vec![
                "find".into(),
                "find_by_id".into(),
                "get".into(),
                "load".into(),
                "fetch".into(),
                "lookup".into(),
                "list".into(),
                "read".into(),
                "query".into(),
            ],
            token_lookup_names: vec![
                "find_by_token".into(),
                "lookup_by_token".into(),
                "get_by_token".into(),
                "find_invitation_by_token".into(),
                "find_invite_by_token".into(),
                "lookup_invitation".into(),
                "get_invitation".into(),
                "find_by_invite_token".into(),
                "find_by_invitation_token".into(),
                "find_signed".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiresat".into(),
                "expiresAt".into(),
                "expiry".into(),
                "expires".into(),
                "expired".into(),
                "valid_until".into(),
                "validUntil".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientEmail".into(),
                "invited_email".into(),
                "invitedEmail".into(),
                "invitee_email".into(),
                "inviteeEmail".into(),
                "recipient".into(),
            ],
            non_sink_receiver_types: vec![
                "HashMap".into(),
                "HashSet".into(),
                "BTreeMap".into(),
                "BTreeSet".into(),
                "Vec".into(),
                "VecDeque".into(),
                "BinaryHeap".into(),
                "IndexMap".into(),
                "IndexSet".into(),
                "LinkedList".into(),
                "SmallVec".into(),
                "FxHashMap".into(),
                "FxHashSet".into(),
                "DashMap".into(),
                "DashSet".into(),
                // `serde_json::Map` (last-segment `Map`), common JSON
                // body builder where `m.insert("k", v)` is a string-key
                // assignment on an in-memory object, not a DB write.
                "Map".into(),
            ],
            non_sink_receiver_name_prefixes: vec![
                "local_map".into(),
                "local_set".into(),
                "local_cache".into(),
                "visited".into(),
                "seen".into(),
                "idx_".into(),
                "index_".into(),
                "lookup_".into(),
                "_tmp_map".into(),
                "counts".into(),
                "buckets".into(),
                "pending".into(),
                "queue".into(),
                "stack".into(),
            ],
            non_sink_global_receivers: Vec::new(),
            non_sink_method_names: Vec::new(),
            realtime_receiver_prefixes: vec![
                "realtime".into(),
                "pubsub".into(),
                "broker".into(),
                "broadcast".into(),
                "notifier".into(),
                "channels".into(),
            ],
            outbound_network_receiver_prefixes: vec![
                "http".into(),
                "reqwest".into(),
                "hyper".into(),
                "client".into(),
                "webhook".into(),
                "fetcher".into(),
            ],
            cache_receiver_prefixes: vec!["redis".into(), "memcache".into(), "memcached".into()],
            acl_tables: vec![
                "group_members".into(),
                "org_memberships".into(),
                "workspace_members".into(),
                "tenant_members".into(),
                "members".into(),
                "share_grants".into(),
            ],
            db_query_builder_roots: Vec::new(),
            authorization_scope_segments: Vec::new(),
            actor_scope_segments: Vec::new(),
        }
    } else {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec!["requireAdmin".into(), "isAdmin".into(), "adminOnly".into()],
            login_guard_names: vec![
                "requireLogin".into(),
                "authenticate".into(),
                "requireAuth".into(),
                "ensureAuthenticated".into(),
                "ensureAuth".into(),
                "require_login".into(),
            ],
            policy_guard_names: Vec::new(),
            authorization_check_names: vec![
                "checkMembership".into(),
                "hasWorkspaceMembership".into(),
                "checkOwnership".into(),
                "authorize".into(),
                "hasAccess".into(),
                "isOwner".into(),
                "isMember".into(),
                "requireMembership".into(),
                "requireOwnership".into(),
                "verifyAccess".into(),
                "hasPermission".into(),
                "requireRole".into(),
                "canAccess".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "delete".into(),
                "create".into(),
                "archive".into(),
                "publish".into(),
                "remove".into(),
                "insert".into(),
                "add".into(),
                "confirm".into(),
                "invite".into(),
                "run".into(),
                "accept".into(),
                // Sequelize `Model.destroy({ where })`, `Model.upsert(row)`.
                "destroy".into(),
                "bulkDestroy".into(),
                "upsert".into(),
            ],
            read_indicator_names: vec![
                "findById".into(),
                "find".into(),
                "list".into(),
                "get".into(),
                "fetch".into(),
                "load".into(),
            ],
            token_lookup_names: vec!["findByToken".into(), "lookupByToken".into()],
            token_expiry_fields: vec!["expires_at".into(), "expiresAt".into(), "expiry".into()],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientEmail".into(),
                "invited_email".into(),
                "invitedEmail".into(),
            ],
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            // Browser/DOM globals, calls on these receivers are
            // categorically client-side (no server-side authorization
            // semantics).  Without this list, `document.getElementById`
            // would prefix-match the read-indicator `get`,
            // `window.scrollTo` would match `scroll`, etc.  Case-sensitive
            // exact match against the first receiver-chain segment.
            non_sink_global_receivers: vec![
                "document".into(),
                "window".into(),
                "localStorage".into(),
                "sessionStorage".into(),
                "console".into(),
                "navigator".into(),
                "location".into(),
                "history".into(),
                "screen".into(),
                "performance".into(),
                "crypto".into(),
                "Math".into(),
                "JSON".into(),
                "Date".into(),
                "Number".into(),
                "String".into(),
                "Boolean".into(),
                "Array".into(),
                "Object".into(),
                "Promise".into(),
                "Symbol".into(),
                "RegExp".into(),
                "Error".into(),
                "Map".into(),
                "Set".into(),
                "WeakMap".into(),
                "WeakSet".into(),
            ],
            // DOM-API methods, when the LAST segment of the callee
            // matches, the call is non-data-layer regardless of receiver
            // (`el.addEventListener`, `parent.appendChild`).  These
            // methods would otherwise prefix-match `add`, `remove`,
            // `get`, `set` indicators.
            non_sink_method_names: vec![
                "addEventListener".into(),
                "removeEventListener".into(),
                "dispatchEvent".into(),
                "appendChild".into(),
                "removeChild".into(),
                "replaceChild".into(),
                "insertBefore".into(),
                "cloneNode".into(),
                "getElementById".into(),
                "getElementsByClassName".into(),
                "getElementsByTagName".into(),
                "getElementsByName".into(),
                "querySelector".into(),
                "querySelectorAll".into(),
                "getAttribute".into(),
                "setAttribute".into(),
                "removeAttribute".into(),
                "hasAttribute".into(),
                "toggleAttribute".into(),
                "createElement".into(),
                "createTextNode".into(),
                "createDocumentFragment".into(),
                "getBoundingClientRect".into(),
                "getComputedStyle".into(),
                "scrollIntoView".into(),
                "scrollTo".into(),
                "scrollBy".into(),
                "focus".into(),
                "blur".into(),
                "submit".into(),
                "reset".into(),
                "click".into(),
                "matches".into(),
                "contains".into(),
                "closest".into(),
                "getItem".into(),
                "setItem".into(),
                "removeItem".into(),
                // Schema and model registry lookups (`strapi.getModel(uid)`,
                // `strapi.getContentType(uid)`) return metadata about a model,
                // not a row, and `createQueryBuilder(uid)` only builds a
                // query.
                "getModel".into(),
                "getModels".into(),
                "getContentType".into(),
                "getContentTypes".into(),
                "getComponent".into(),
                "getComponents".into(),
                "createQueryBuilder".into(),
            ],
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
            db_query_builder_roots: Vec::new(),
            authorization_scope_segments: Vec::new(),
            actor_scope_segments: Vec::new(),
        }
    };

    for config_slug in auth_config_slugs(lang_slug) {
        let Some(lang_cfg) = config.analysis.languages.get(*config_slug) else {
            continue;
        };
        rules.enabled = lang_cfg.auth.enabled;
        extend_unique(
            &mut rules.admin_path_patterns,
            &lang_cfg.auth.admin_path_patterns,
        );
        extend_unique(
            &mut rules.admin_guard_names,
            &lang_cfg.auth.admin_guard_names,
        );
        extend_unique(
            &mut rules.login_guard_names,
            &lang_cfg.auth.login_guard_names,
        );
        extend_unique(
            &mut rules.policy_guard_names,
            &lang_cfg.auth.policy_guard_names,
        );
        extend_unique(
            &mut rules.authorization_check_names,
            &lang_cfg.auth.authorization_check_names,
        );
        extend_unique(
            &mut rules.mutation_indicator_names,
            &lang_cfg.auth.mutation_indicator_names,
        );
        extend_unique(
            &mut rules.read_indicator_names,
            &lang_cfg.auth.read_indicator_names,
        );
        extend_unique(
            &mut rules.token_lookup_names,
            &lang_cfg.auth.token_lookup_names,
        );
        extend_unique(
            &mut rules.token_expiry_fields,
            &lang_cfg.auth.token_expiry_fields,
        );
        extend_unique(
            &mut rules.token_recipient_fields,
            &lang_cfg.auth.token_recipient_fields,
        );
        extend_unique(
            &mut rules.non_sink_receiver_types,
            &lang_cfg.auth.non_sink_receiver_types,
        );
        extend_unique(
            &mut rules.non_sink_receiver_name_prefixes,
            &lang_cfg.auth.non_sink_receiver_name_prefixes,
        );
        extend_unique(
            &mut rules.non_sink_global_receivers,
            &lang_cfg.auth.non_sink_global_receivers,
        );
        extend_unique(
            &mut rules.non_sink_method_names,
            &lang_cfg.auth.non_sink_method_names,
        );
        extend_unique(
            &mut rules.realtime_receiver_prefixes,
            &lang_cfg.auth.realtime_receiver_prefixes,
        );
        extend_unique(
            &mut rules.outbound_network_receiver_prefixes,
            &lang_cfg.auth.outbound_network_receiver_prefixes,
        );
        extend_unique(
            &mut rules.cache_receiver_prefixes,
            &lang_cfg.auth.cache_receiver_prefixes,
        );
        extend_unique(&mut rules.acl_tables, &lang_cfg.auth.acl_tables);
        extend_unique(
            &mut rules.db_query_builder_roots,
            &lang_cfg.auth.db_query_builder_roots,
        );
    }

    rules
}

pub fn extend_unique(dst: &mut Vec<String>, src: &[String]) {
    for item in src {
        if !dst.contains(item) {
            dst.push(item.clone());
        }
    }
}

pub fn canonical_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Return the first segment of a callee's receiver chain.
/// For `map.insert` → `"map"`; for `self.cache.insert` → `"self"`;
/// for a callee with no receiver (`HashMap::new`) → the full name.
pub fn first_receiver_segment(callee: &str) -> &str {
    callee.split('.').next().unwrap_or(callee)
}

/// True when the callee's receiver chain contains a call expression ,
/// i.e. the LAST segment is being invoked on the *return value* of an
/// earlier call (`w.Header().Get`, `r.URL.Query().Get`,
/// `db.Tx(opts).Query`).  Detected as: the substring before the last
/// `.` contains a `(`.
///
/// `classify_sink_class` consults this to suppress the loose verb-name
/// fallback (`is_read` / `is_mutation`) for chained-call shapes whose
/// receiver type is opaque to the analyser.
pub fn receiver_is_chained_call(callee: &str) -> bool {
    let Some((receiver, _method)) = callee.rsplit_once('.') else {
        return false;
    };
    receiver.contains('(')
}

/// True when the receiver's last segment is named like an id or a collection
/// of ids (`uniqueIDs.Remove`, `r.configVersionID.Load`).  Chained-call
/// receivers are left to the other rules.
fn receiver_is_id_value(callee: &str) -> bool {
    let Some((receiver, _method)) = callee.rsplit_once('.') else {
        return false;
    };
    if receiver.contains('(') {
        return false;
    }
    let last = receiver.rsplit('.').next().unwrap_or(receiver);
    crate::auth_analysis::naming::is_id_like_name(last)
}

/// Go struct fields that hold request data.  A call made through one of them
/// (`r.Form.Get`, `req.Header.Add`, `r.PostForm.Set`) reads or edits the
/// request, not a data store.
const GO_REQUEST_DATA_FIELDS: &[&str] = &[
    "Header",
    "Form",
    "PostForm",
    "MultipartForm",
    "Trailer",
    "URL",
];

fn receiver_passes_through_request_data(callee: &str) -> bool {
    let Some((receiver, _method)) = callee.rsplit_once('.') else {
        return false;
    };
    // Chained-call receivers (`r.URL.Query().Get`) already skip the verb
    // fallback in `classify_sink_class`.
    if receiver.contains('(') {
        return false;
    }
    receiver
        .split('.')
        .skip(1)
        .any(|segment| GO_REQUEST_DATA_FIELDS.contains(&segment))
}

/// True when the callee has a non-chained receiver dot, i.e. an actual
/// receiver identifier or path (`User.find`, `repo.save`,
/// `Model.objects.filter`).  Returns false for bare-identifier callees
/// (`list(..)`, `filter(..)`, `create_audit_entry(..)`) and for
/// chained-call receivers (`db.Tx(..).Query(..)`) — both lack the
/// receiver evidence needed to anchor a DB-sink classification, see
/// the comment in `classify_sink_class`.
pub fn receiver_is_simple_chain(callee: &str) -> bool {
    callee.contains('.') && !receiver_is_chained_call(callee)
}

/// Recognise `require_<resource>_<role>` / `ensure_<resource>_<role>`
/// shapes where `<role>` is a closed-vocabulary authorization noun
/// (`member`, `owner`, `admin`, `access`, `permission`, `manager`,
/// `editor`, `viewer`, `user`, `mod`).  The resource segment is
/// project-specific (`trip`, `doc`, `project`, `community`, …) and
/// cannot be enumerated in the static defaults, but the
/// prefix+role pattern is unambiguous enough that recognising it as
/// an authorization check is safe.  Also accepts `is_<role>` /
/// `is_<role>_(or|and)_<role>...` predicate forms (`is_admin`,
/// `is_mod_or_admin`).
///
/// Strips path-namespace and method prefixes before matching:
/// `authz::require_trip_member` → `require_trip_member`;
/// `obj.require_trip_member` → `require_trip_member`.
fn is_require_resource_role_call(name: &str) -> bool {
    let last = name.rsplit("::").next().unwrap_or(name);
    let last = last.rsplit('.').next().unwrap_or(last);
    let lower = last.to_ascii_lowercase();

    // Pattern 1: `<verb>_<resource>_<role>[_<context>]?` where
    // <verb> ∈ {require, ensure, check, assert, verify} and
    // <context> ∈ {action, allowed, valid} (a small closed suffix
    // set that wraps the role, e.g. `check_community_mod_action`).
    if let Some(after_prefix) = strip_auth_verb_prefix(&lower) {
        let core = strip_role_context_suffix(after_prefix);
        if let Some(last_underscore) = core.rfind('_')
            && last_underscore > 0
            && last_underscore < core.len() - 1
        {
            let role = &core[last_underscore + 1..];
            if is_known_auth_role(role) {
                return true;
            }
        }
    }

    // Pattern 2: `is_<role>` and `is_<role>_(or|and)_<role>...`.
    // Conservative role list, excludes `user` / `staff` to avoid
    // matching ambiguous predicates like `is_user`.
    if let Some(rest) = lower.strip_prefix("is_")
        && !rest.is_empty()
        && all_tokens_are_predicate_roles(rest)
    {
        return true;
    }

    false
}

fn strip_auth_verb_prefix(lower: &str) -> Option<&str> {
    for verb in ["require_", "ensure_", "check_", "assert_", "verify_"] {
        if let Some(rest) = lower.strip_prefix(verb) {
            return Some(rest);
        }
    }
    None
}

/// Strip a single trailing `_<context>` suffix where <context> wraps
/// a role word with extra noise (`_action` / `_allowed` / `_valid`).
/// Does NOT strip `_access` / `_permission` because those are
/// themselves valid role suffixes (`require_doc_access`).
fn strip_role_context_suffix(s: &str) -> &str {
    for suffix in ["_action", "_allowed", "_valid"] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            return stripped;
        }
    }
    s
}

fn is_known_auth_role(role: &str) -> bool {
    matches!(
        role,
        "member"
            | "members"
            | "owner"
            | "owners"
            | "admin"
            | "admins"
            | "access"
            | "permission"
            | "permissions"
            | "manager"
            | "managers"
            | "editor"
            | "editors"
            | "viewer"
            | "viewers"
            | "role"
            | "user"
            | "mod"
            | "mods"
            | "moderator"
            | "moderators"
    )
}

/// `is_<role>` predicate role set.  Tighter than the
/// `<verb>_<resource>_<role>` set because predicates lack the
/// resource segment that disambiguates ambiguous role nouns
/// (`is_user` could be a typeof check, not an authorization check).
fn is_predicate_auth_role(role: &str) -> bool {
    matches!(
        role,
        "admin"
            | "admins"
            | "owner"
            | "owners"
            | "member"
            | "members"
            | "manager"
            | "managers"
            | "moderator"
            | "moderators"
            | "mod"
            | "mods"
            | "editor"
            | "editors"
    )
}

/// Returns `true` iff every `_or_` / `_and_`-separated token in `rest`
/// is a known predicate auth role.  E.g. `mod_or_admin` → true,
/// `mod_or_owner_and_admin` → true, `mod_or_logged_in` → false.
fn all_tokens_are_predicate_roles(rest: &str) -> bool {
    let mut tokens: Vec<&str> = vec![rest];
    for sep in &["_or_", "_and_"] {
        let mut next: Vec<&str> = Vec::new();
        for t in &tokens {
            for piece in t.split(sep) {
                next.push(piece);
            }
        }
        tokens = next;
    }
    !tokens.is_empty() && tokens.iter().all(|t| is_predicate_auth_role(t))
}

/// True iff the canonical form of `pattern` (ascii-alphanumeric only,
/// lowercased) is non-empty and is a prefix of the canonical form of
/// `name`.  This streams the canonical bytes of both operands without
/// allocating, replacing two throwaway `canonical_name` `String`
/// allocations per comparison.
///
/// Bit-identical to `!pattern_norm.is_empty() && (name_norm == pattern_norm
/// || name_norm.starts_with(&pattern_norm))` where `name_norm` /
/// `pattern_norm` are `canonical_name(name)` / `canonical_name(pattern)`
/// (the `==` disjunct is the equal-length case of `starts_with`, so the
/// whole condition reduces to a non-empty-pattern prefix test).
///
/// The byte filter is equivalent to `canonical_name`'s
/// `chars().filter(char::is_ascii_alphanumeric)`: `canonical_name` keeps
/// only ASCII-alphanumeric chars (each a single ASCII byte) and every byte
/// of a multi-byte UTF-8 char is `>= 0x80`, so `u8::is_ascii_alphanumeric`
/// drops all of them — the surviving byte stream is identical.
fn canon_has_prefix(name: &str, pattern: &str) -> bool {
    let mut name_bytes = name.bytes().filter(u8::is_ascii_alphanumeric);
    let mut saw_pattern = false;
    for pb in pattern.bytes().filter(u8::is_ascii_alphanumeric) {
        saw_pattern = true;
        match name_bytes.next() {
            Some(nb) if nb.eq_ignore_ascii_case(&pb) => {}
            _ => return false,
        }
    }
    saw_pattern
}

/// Escape hatch / single-binary A-B: `NYX_DISABLE_CANON_STREAM=1` forces the
/// legacy allocating `canonical_name`-based comparison in `matches_name`.
fn canon_stream_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| std::env::var("NYX_DISABLE_CANON_STREAM").is_ok())
}

pub fn matches_name(name: &str, pattern: &str) -> bool {
    let name_last = name.rsplit('.').next().unwrap_or(name);
    let pattern_last = pattern.rsplit('.').next().unwrap_or(pattern);
    if canon_stream_disabled() {
        let name_norm = canonical_name(name_last);
        let pattern_norm = canonical_name(pattern_last);
        return !pattern_norm.is_empty()
            && (name_norm == pattern_norm || name_norm.starts_with(&pattern_norm));
    }
    canon_has_prefix(name_last, pattern_last)
}

/// `<receiver>.get(..)` and `<receiver>.get_*(..)` whose receiver shows no ORM:
/// not a manager (`objects`), a query property (`Model.query`), a session
/// (`db.session`) or a queryset chain (`Model.objects.select_related(..).get`).
/// Off an ORM these are dictionary lookups (`options.get(k)`), HTTP clients
/// (`client.get(url)`) and ordinary object methods (`group.get_absolute_url`).
fn is_non_orm_get(callee: &str, orm_models: &std::collections::HashSet<String>) -> bool {
    const ORM_SEGMENTS: &[&str] = &[
        "objects",
        "query",
        "session",
        "_default_manager",
        "_base_manager",
        "select_related",
        "prefetch_related",
        "select_for_update",
        "only",
        "defer",
        "filter",
        "exclude",
        "all",
        "annotate",
        "using",
        "order_by",
        "distinct",
        // DRF views keep their rows on `self.queryset`.
        "queryset",
    ];
    let Some((receiver, method)) = callee.rsplit_once('.') else {
        return false;
    };
    // `get_object_or_404(..)` reached through a module (`shortcuts.get_object_or_404`)
    // and `get_or_create` / `get_or_none` read or write rows whatever the receiver.
    if method.starts_with("get_object_or") || method.starts_with("get_or_") {
        return false;
    }
    // A bare `.get` on a class is as often a registry or settings lookup
    // (`Settings.get(key)`, `Cache.get(item_id)`) as a model read, so a
    // PascalCase receiver counts only for the ORM-only `get_by_*` spellings
    // (`Note.get_by_id(pk)`), or for a class the file derives from the peewee
    // or tortoise `Model` (`orm_models`).
    let model_lookup = method.starts_with("get_by");
    matches_name(method, "get")
        && !receiver.split('.').any(|segment| {
            let segment = segment.trim_end_matches("()");
            ORM_SEGMENTS.contains(&segment)
                || is_queryset_variable(segment)
                || (model_lookup && is_model_class_name(segment))
                || orm_models.contains(segment)
        })
}

/// `qs`, `queryset`, `active_qs`, `user_queryset`: a variable that holds a
/// queryset.
fn is_queryset_variable(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    lower == "qs" || lower.ends_with("_qs") || lower.ends_with("queryset")
}

/// A model class, as in Peewee's `Note.get_by_id(..)`.  Model classes are
/// PascalCase; an all-caps name (`GET`, `QUERY`) is a constant.
fn is_model_class_name(segment: &str) -> bool {
    segment
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
        && segment.chars().any(|c| c.is_ascii_lowercase())
}

/// Names of role-gating middleware: the roles they accept are arguments, so
/// the call is an admin guard only when those arguments name admin roles.
fn is_role_gate_name(name: &str) -> bool {
    [
        "authorize",
        "checkRole",
        "requireRole",
        "requireRoles",
        "restrictTo",
    ]
    .iter()
    .any(|gate| matches_name(name, gate))
}

/// A role or authority name that only privileged users hold: `ADMIN`,
/// `ROLE_ADMIN`, `MANAGER`, `superuser`, `MANAGE_USERS`.
///
/// The name is read as words (split on punctuation and camel-case humps), so
/// `ROLE_ADMIN` and `siteAdmin` are privileged while a word that merely
/// contains one is not.  A qualifier that narrows the grant (`MANAGE_OWN_NOTES`,
/// `ADMIN_READONLY`, `NON_ADMIN`) makes the name an ordinary role.
fn names_privileged_role(role: &str) -> bool {
    const PRIVILEGED: &[&str] = &[
        "admin",
        "administrator",
        "superuser",
        "superadmin",
        "sysadmin",
        "root",
        "manage",
        "manager",
    ];
    const NARROWING: &[&str] = &[
        "non", "not", "no", "own", "self", "read", "readonly", "view", "viewer", "limited",
        "guest", "demo",
    ];
    let words = role_words(role);
    words.iter().any(|word| PRIVILEGED.contains(&word.as_str()))
        && !words.iter().any(|word| NARROWING.contains(&word.as_str()))
}

/// Lowercase words of a role name: `ROLE_ADMIN` -> `role admin`,
/// `siteAdmin` -> `site admin`, `users:manage` -> `users manage`.
fn role_words(role: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for ch in role.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        if ch.is_ascii_uppercase() && prev_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        prev_lower = ch.is_ascii_lowercase();
        current.push(ch.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// True when the arguments name at least one role and every role they name is
/// privileged.  A role is a string literal, alone or inside an array literal
/// (`'admin'`, `['admin', 'owner']`); an argument with no string literal
/// (`Roles.ADMIN`) is one role spelled by its expression.
fn every_role_is_privileged(args: &[String]) -> bool {
    let mut roles = Vec::new();
    for arg in args {
        let literals = string_literals(arg);
        if literals.is_empty() {
            roles.push(arg.trim().to_string());
        } else {
            roles.extend(literals);
        }
    }
    !roles.is_empty() && roles.iter().all(|role| names_privileged_role(role))
}

/// Contents of the `'..'`, `".."` and backtick literals in `text`.
fn string_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if matches!(ch, '\'' | '"' | '`') {
            let literal: String = chars.by_ref().take_while(|c| *c != ch).collect();
            out.push(literal);
        }
    }
    out
}

/// Separator between a callee's receiver segments: `Invitation.objects.get`
/// (Python, JS, Ruby) and `Accounts::Invitation.find_by` (Ruby, Rust).
fn is_path_separator(c: char) -> bool {
    c == '.' || c == ':'
}

/// True when two segments read the same once punctuation and case are dropped.
fn canon_eq(a: &str, b: &str) -> bool {
    let mut a = a.bytes().filter(u8::is_ascii_alphanumeric);
    let mut b = b.bytes().filter(u8::is_ascii_alphanumeric);
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if x.eq_ignore_ascii_case(&y) => {}
            _ => return false,
        }
    }
}

/// Like [`matches_name`], but a dotted `pattern` keeps its receiver.
///
/// `matches_name` compares only the last segment, so the pattern
/// `Invitation.objects.get` collapses to `get` and matches every dictionary
/// `.get()` and ORM `.get()` in the program.  Here the callee has to end in the
/// same receiver segments (compared by canonical form, so `::Invitation` and
/// `invitation` agree) and its last segment must start with the pattern's last
/// segment, as in `matches_name`.  A pattern with no separator behaves exactly
/// like `matches_name`.
pub fn matches_qualified_name(name: &str, pattern: &str) -> bool {
    if !pattern.contains(is_path_separator) {
        return matches_name(name, pattern);
    }
    let mut name_segments = name.rsplit(is_path_separator).filter(|s| !s.is_empty());
    let mut pattern_segments = pattern.rsplit(is_path_separator).filter(|s| !s.is_empty());
    let (Some(name_last), Some(pattern_last)) = (name_segments.next(), pattern_segments.next())
    else {
        return false;
    };
    if !canon_has_prefix(name_last, pattern_last) {
        return false;
    }
    pattern_segments.all(|pattern_segment| {
        name_segments
            .next()
            .is_some_and(|name_segment| canon_eq(name_segment, pattern_segment))
    })
}

pub fn strip_quotes(input: &str) -> String {
    input
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .trim_matches('`')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::build_auth_rules;
    use crate::utils::config::{AuthAnalysisConfig, Config, LanguageAnalysisConfig};

    #[test]
    fn qualified_pattern_keeps_its_receiver() {
        use super::matches_qualified_name as m;
        assert!(m("Invitation.objects.get", "Invitation.objects.get"));
        assert!(m("app.Invitation.objects.get", "Invitation.objects.get"));
        assert!(m(
            "invitation.objects.get_or_create",
            "Invitation.objects.get"
        ));
        // Other receivers share the last segment only.
        assert!(!m("request.json.get", "Invitation.objects.get"));
        assert!(!m("Document.objects.get", "Invitation.objects.get"));
        assert!(!m("db.session.get", "Invitation.objects.get"));
        // A bare `get` has no receiver to compare.
        assert!(!m("get", "Invitation.objects.get"));
        // Ruby scope resolution and bang methods.
        assert!(m("Accounts::Invitation.find_by!", "Invitation.find_by"));
        assert!(m("::Invitation.find_by", "Invitation.find_by"));
        assert!(!m("Document.find_by", "Invitation.find_by"));
        assert!(!m("find_by", "Invitation.find_by"));
        // A pattern with no separator is the old last-segment prefix match.
        assert!(m("Invitation.find_by_token", "find_by_token"));
        assert!(m("store.findByToken", "findByToken"));
        assert!(!m("store.find", "findByToken"));
    }

    #[test]
    fn default_token_lookups_need_their_receiver() {
        let cfg = Config::default();
        let python = build_auth_rules(&cfg, "python");
        assert!(python.is_token_lookup("Invitation.objects.get"));
        assert!(python.is_token_lookup("invitation_lookup"));
        assert!(python.is_token_lookup("store.find_by_token"));
        assert!(!python.is_token_lookup("Document.objects.get"));
        assert!(!python.is_token_lookup("request.json.get"));
        assert!(!python.is_token_lookup("db.session.get"));

        let ruby = build_auth_rules(&cfg, "ruby");
        assert!(ruby.is_token_lookup("Invitation.find_by"));
        assert!(ruby.is_token_lookup("Invite.find_by!"));
        assert!(ruby.is_token_lookup("Invitation.find_by_token"));
        assert!(!ruby.is_token_lookup("Document.find_by"));
        assert!(!ruby.is_token_lookup("Document.find_by!"));
    }

    #[test]
    fn python_get_is_a_row_read_only_on_an_orm_receiver() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let rules = build_auth_rules(&Config::default(), "python");
        let none = HashSet::new();
        let class = |callee: &str| rules.classify_sink_class(callee, &none);
        for orm in [
            "Document.objects.get",
            "db.session.get",
            "Note.query.get",
            "Document.objects.select_related().get",
            "self.model._default_manager.get",
            "Project.objects.get_from_cache",
        ] {
            assert_eq!(class(orm), Some(SinkClass::DbCrossTenantRead), "{orm}");
        }
        for plain in [
            "options.get",
            "titles_by_id.get",
            "cache.get",
            "request.GET.get",
            "self.object.project.statuses.get",
            "group.get_absolute_url",
            "integration_service.get_integration",
            "dag.get_task",
        ] {
            assert_eq!(class(plain), None, "{plain}");
        }
        // Other verbs keep their old classification.
        assert_eq!(
            class("Document.objects.filter"),
            Some(SinkClass::DbCrossTenantRead)
        );
    }

    #[test]
    fn role_gates_are_admin_guards_only_for_an_admin_role() {
        let rules = build_auth_rules(&Config::default(), "javascript");
        let admin = |name: &str, args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            rules.is_admin_guard(name, &args)
        };
        assert!(admin("authorize", &["'admin'"]));
        assert!(admin("checkRole", &["['admin']"]));
        assert!(admin("checkRole", &["['admin', 'superadmin']"]));
        assert!(admin("restrictTo", &["\"admin\""]));
        assert!(admin("authorize", &["Roles.ADMIN"]));
        assert!(!admin("authorize", &["'viewer'"]));
        assert!(!admin("checkRole", &["['viewer']"]));
        assert!(!admin("authorize", &[]));
        // Any listed role is let in, so one ordinary role is enough to make
        // the gate a non-admin one.
        assert!(!admin("checkRole", &["['admin', 'viewer']"]));
        assert!(!admin("restrictTo", &["'admin'", "'user'"]));
        // An ownership call that happens to share the name is not a role gate.
        assert!(!admin("authorize", &["req.user", "doc"]));
    }

    #[test]
    fn python_get_on_querysets_and_model_classes_is_a_row_read() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let rules = build_auth_rules(&Config::default(), "python");
        let none = HashSet::new();
        for orm in [
            "self.queryset.get",
            "qs.get",
            "active_qs.get",
            "note_queryset.get",
            "Note.get_by_id",
            "shortcuts.get_object_or_404",
            "Note.objects.get_or_create",
        ] {
            assert_eq!(
                rules.classify_sink_class(orm, &none),
                Some(SinkClass::DbCrossTenantRead),
                "{orm}"
            );
        }
        for plain in [
            "options.get",
            "request.GET.get",
            "client.get",
            "Settings.get",
            "Cache.get",
            "FeatureFlags.get",
        ] {
            assert_eq!(rules.classify_sink_class(plain, &none), None, "{plain}");
        }
    }

    #[test]
    fn secured_and_roles_allowed_need_every_role_to_be_privileged() {
        let rules = build_auth_rules(&Config::default(), "java");
        let args =
            |values: &[&str]| -> Vec<String> { values.iter().map(|v| v.to_string()).collect() };
        assert!(rules.is_admin_guard("Secured", &args(&["ROLE_ADMIN"])));
        assert!(rules.is_admin_guard("RolesAllowed", &args(&["ADMIN", "SUPERUSER"])));
        assert!(!rules.is_admin_guard("Secured", &args(&["ROLE_ADMIN", "ROLE_USER"])));
        assert!(!rules.is_admin_guard("RolesAllowed", &args(&["ADMIN", "USER"])));
        // Roles that contain an admin word without being privileged.
        for role in [
            "MANAGE_OWN_NOTES",
            "ROLE_ADMIN_READONLY",
            "NON_ADMIN",
            "RADMINISTRATIVE",
        ] {
            assert!(!rules.is_admin_guard("hasRole", &args(&[role])), "{role}");
        }
        for role in [
            "ADMIN",
            "ROLE_ADMIN",
            "siteAdmin",
            "MANAGE_USERS",
            "superuser",
        ] {
            assert!(rules.is_admin_guard("hasRole", &args(&[role])), "{role}");
        }
    }

    #[test]
    fn require_roles_is_decided_by_its_arguments() {
        let rules = build_auth_rules(&Config::default(), "javascript");
        let args =
            |values: &[&str]| -> Vec<String> { values.iter().map(|v| v.to_string()).collect() };
        assert!(!rules.is_admin_guard("requireRoles", &args(&["'viewer'"])));
        assert!(!rules.is_admin_guard("requireRole", &args(&["'viewer'"])));
        assert!(rules.is_admin_guard("requireRoles", &args(&["'admin'"])));
        assert!(rules.is_admin_guard("requireRole", &args(&["'admin'"])));
        assert!(!rules.is_admin_guard("requireRoles", &args(&["'admin'", "'viewer'"])));
    }

    #[test]
    fn has_any_role_follows_has_role() {
        let rules = build_auth_rules(&Config::default(), "java");
        let args =
            |values: &[&str]| -> Vec<String> { values.iter().map(|v| v.to_string()).collect() };
        assert!(rules.is_admin_guard("hasAnyRole", &args(&["ADMIN", "MANAGER"])));
        assert!(rules.is_admin_guard("hasAnyAuthority", &args(&["ROLE_ADMIN"])));
        assert!(!rules.is_admin_guard("hasAnyRole", &args(&["USER", "EDITOR"])));
        // `hasAnyRole('ADMIN', 'USER')` lets every user in.
        assert!(!rules.is_admin_guard("hasAnyRole", &args(&["ADMIN", "USER"])));
        assert!(!rules.is_admin_guard("hasAnyAuthority", &args(&["ROLE_ADMIN", "ROLE_USER"])));
        assert!(!rules.is_admin_guard("hasAnyRole", &args(&[])));
        // A role list is a login-level guard even when it names no admin role.
        assert!(rules.is_login_guard("hasAnyRole"));
        assert!(rules.is_login_guard("hasAnyAuthority"));
    }

    #[test]
    fn typescript_uses_javascript_rule_prefix() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "typescript");
        assert_eq!(
            rules.rule_id("missing_ownership_check"),
            "js.auth.missing_ownership_check"
        );
    }

    #[test]
    fn typescript_inherits_javascript_auth_overrides_and_applies_ts_specific_overlay() {
        let mut cfg = Config::default();
        cfg.analysis.languages.insert(
            "javascript".into(),
            LanguageAnalysisConfig {
                auth: AuthAnalysisConfig {
                    admin_guard_names: vec!["requirePlatformAdmin".into()],
                    token_lookup_names: vec!["findInviteToken".into()],
                    ..AuthAnalysisConfig::default()
                },
                ..LanguageAnalysisConfig::default()
            },
        );
        cfg.analysis.languages.insert(
            "typescript".into(),
            LanguageAnalysisConfig {
                auth: AuthAnalysisConfig {
                    authorization_check_names: vec!["requireTypedOwnership".into()],
                    ..AuthAnalysisConfig::default()
                },
                ..LanguageAnalysisConfig::default()
            },
        );

        let rules = build_auth_rules(&cfg, "typescript");

        assert!(
            rules
                .admin_guard_names
                .contains(&"requirePlatformAdmin".to_string())
        );
        assert!(
            rules
                .token_lookup_names
                .contains(&"findInviteToken".to_string())
        );
        assert!(
            rules
                .authorization_check_names
                .contains(&"requireTypedOwnership".to_string())
        );
    }

    #[test]
    fn rust_non_sink_receiver_defaults_include_std_collections() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        assert!(rules.is_non_sink_receiver_type("HashMap"));
        assert!(rules.is_non_sink_receiver_type("HashSet"));
        assert!(rules.is_non_sink_receiver_type("Vec"));
        assert!(rules.is_non_sink_receiver_type("std::collections::HashMap"));
        assert!(rules.is_non_sink_receiver_type("HashMap<i64, usize>"));
        assert!(!rules.is_non_sink_receiver_type("Database"));
    }

    #[test]
    fn rust_non_sink_constructor_callee_matches_known_forms() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        assert!(rules.is_non_sink_constructor_callee("HashMap::new"));
        assert!(rules.is_non_sink_constructor_callee("HashMap::with_capacity"));
        assert!(rules.is_non_sink_constructor_callee("SmallVec::from"));
        assert!(rules.is_non_sink_constructor_callee("std::collections::HashMap::new"));
        assert!(!rules.is_non_sink_constructor_callee("HashMap::get"));
        assert!(!rules.is_non_sink_constructor_callee("Database::connect"));
        assert!(!rules.is_non_sink_constructor_callee("plain_function"));
    }

    #[test]
    fn callee_has_non_sink_receiver_matches_var_set_and_prefixes() {
        use std::collections::HashSet;
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        let mut vars = HashSet::new();
        vars.insert("map".to_string());

        // First receiver segment in non_sink_vars → skipped.
        assert!(rules.callee_has_non_sink_receiver("map.insert", &vars));
        // First segment not in vars, not a known prefix → not skipped.
        assert!(!rules.callee_has_non_sink_receiver("db.insert", &vars));
        // Deep receiver: "self.cache.insert" → first segment "self" → ambiguous.
        assert!(!rules.callee_has_non_sink_receiver("self.cache.insert", &vars));
        // Prefix-match on configured name prefix ("counts" is in defaults).
        assert!(rules.callee_has_non_sink_receiver("counts.insert", &HashSet::new()));
        assert!(rules.callee_has_non_sink_receiver("visited_nodes.insert", &HashSet::new()));
    }

    #[test]
    fn classify_sink_class_dispatches_on_receiver_and_name() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        let mut vars = HashSet::new();
        vars.insert("map".to_string());

        // In-memory local: tracked var → InMemoryLocal (trumps name-based match).
        assert_eq!(
            rules.classify_sink_class("map.insert", &vars),
            Some(SinkClass::InMemoryLocal)
        );
        // In-memory local: configured name prefix.
        assert_eq!(
            rules.classify_sink_class("visited.insert", &HashSet::new()),
            Some(SinkClass::InMemoryLocal)
        );
        // Realtime: default prefix `realtime` → RealtimePublish even when
        // the method name (`publish_to_group`) would also match the
        // mutation list.
        assert_eq!(
            rules.classify_sink_class("realtime.publish_to_group", &HashSet::new()),
            Some(SinkClass::RealtimePublish)
        );
        // Outbound network: default prefix `http`.
        assert_eq!(
            rules.classify_sink_class("http.post", &HashSet::new()),
            Some(SinkClass::OutboundNetwork)
        );
        // Cache: default prefix `redis`.
        assert_eq!(
            rules.classify_sink_class("redis.set", &HashSet::new()),
            Some(SinkClass::CacheCrossTenant)
        );
        // DB mutation fallback: `db.insert` → mutation indicator →
        // DbMutation (no receiver prefix matches `db`).
        assert_eq!(
            rules.classify_sink_class("db.insert", &HashSet::new()),
            Some(SinkClass::DbMutation)
        );
        // DB cross-tenant read fallback: `db.find_by_id` → read indicator.
        assert_eq!(
            rules.classify_sink_class("db.find_by_id", &HashSet::new()),
            Some(SinkClass::DbCrossTenantRead)
        );
        // Unknown verb with unknown receiver → None.
        assert_eq!(
            rules.classify_sink_class("widget.frobnicate", &HashSet::new()),
            None
        );
    }

    #[test]
    fn receiver_is_chained_call_detects_intermediate_calls() {
        use super::receiver_is_chained_call;
        // Chained-call shape: receiver chain contains a `(`.
        assert!(receiver_is_chained_call("w.Header().Get"));
        assert!(receiver_is_chained_call("r.URL.Query().Get"));
        assert!(receiver_is_chained_call("db.Tx(opts).Query"));
        assert!(receiver_is_chained_call("client.WithToken(t).Get"));
        // Pure field/identifier chain, no `(` anywhere.
        assert!(!receiver_is_chained_call("repo.Find"));
        assert!(!receiver_is_chained_call("c.Fs.Create"));
        assert!(!receiver_is_chained_call("globalBatchJobsMetrics.save"));
        assert!(!receiver_is_chained_call("self.cache.insert"));
        // Bare callee with no receiver.
        assert!(!receiver_is_chained_call("Get"));
        assert!(!receiver_is_chained_call("HashMap::new"));
    }

    #[test]
    fn classify_sink_class_suppresses_chained_call_verb_fallback() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "go");
        let empty: HashSet<String> = HashSet::new();

        // Chained-call receiver: verb-name fallback is suppressed.
        // The minio `w.Header().Get(constName)` cluster, `Get` would
        // match the `Get` read indicator on a bare receiver but the
        // chained-call shape masks the receiver type.
        assert_eq!(rules.classify_sink_class("w.Header().Get", &empty), None);
        assert_eq!(rules.classify_sink_class("r.URL.Query().Get", &empty), None);
        // Bare-identifier receiver: verb-name fallback still fires.
        // Pin the regression guard so this fix doesn't over-suppress
        // canonical data-layer shapes.
        assert_eq!(
            rules.classify_sink_class("repo.Find", &empty),
            Some(SinkClass::DbCrossTenantRead)
        );
        assert_eq!(
            rules.classify_sink_class("repo.Save", &empty),
            Some(SinkClass::DbMutation)
        );
    }

    /// Pin the bare-identifier verb-fallback gate.  Bare callees with
    /// no receiver dot lack the receiver evidence needed to anchor a
    /// DB-sink classification: `list(...)`, `filter(...)`, `update(...)`,
    /// `create_audit_entry(...)`, `update_coding_agent_state(...)` are
    /// Python builtins / JS Array methods / locally-defined helpers,
    /// not ORM operations.  Closes the sentry / saleor / netbox cluster
    /// where bare-name callees inside route helpers (with `request:
    /// Request` triggering the user-input precondition) fired
    /// `py.auth.missing_ownership_check`.
    #[test]
    fn classify_sink_class_suppresses_bare_callee_verb_fallback() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let empty: HashSet<String> = HashSet::new();

        for lang in [
            "python",
            "javascript",
            "typescript",
            "go",
            "java",
            "ruby",
            "rust",
        ] {
            let cfg = Config::default();
            let rules = build_auth_rules(&cfg, lang);
            // Bare callees that prefix-match a read / mutation indicator
            // must NOT classify as DbCrossTenantRead / DbMutation.
            assert_eq!(
                rules.classify_sink_class("list", &empty),
                None,
                "lang={lang} bare list",
            );
            assert_eq!(
                rules.classify_sink_class("filter", &empty),
                None,
                "lang={lang} bare filter",
            );
            assert_eq!(
                rules.classify_sink_class("update", &empty),
                None,
                "lang={lang} bare update",
            );
            assert_eq!(
                rules.classify_sink_class("create_audit_entry", &empty),
                None,
                "lang={lang} bare create_audit_entry",
            );
            assert_eq!(
                rules.classify_sink_class("update_coding_agent_state", &empty),
                None,
                "lang={lang} bare update_coding_agent_state",
            );
        }

        // Recall guard: qualified ORM / DB calls keep firing on every
        // language that has the verb in its indicator vocabulary.
        let py_rules = build_auth_rules(&Config::default(), "python");
        assert_eq!(
            py_rules.classify_sink_class("Project.objects.filter", &empty),
            Some(SinkClass::DbCrossTenantRead)
        );
        assert_eq!(
            py_rules.classify_sink_class("Project.objects.update", &empty),
            Some(SinkClass::DbMutation)
        );
        let go_rules = build_auth_rules(&Config::default(), "go");
        assert_eq!(
            go_rules.classify_sink_class("repo.Find", &empty),
            Some(SinkClass::DbCrossTenantRead)
        );
    }

    /// Pin the SQLAlchemy queryset-builder chained-call recogniser.
    /// `select(X).filter_by(id=user_input)` reduces (post `member_chain`
    /// fix) to the chain-string `"select().filter_by"`.  The chained-call
    /// shape would otherwise be suppressed by `receiver_is_chained_call`,
    /// blocking recall on the airflow `session.scalar(select(C).filter_by(...))`
    /// shape.  `chain_root_is_db_query_builder` overrides the suppression
    /// when the chain root is a configured DB-builder verb.
    #[test]
    fn chain_root_is_db_query_builder_recognises_sqlalchemy_chains() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let cfg = Config::default();
        let py_rules = build_auth_rules(&cfg, "python");
        let empty: HashSet<String> = HashSet::new();

        // Detection: chain root `select()` / `query()` matches the
        // configured Python `db_query_builder_roots`.
        assert!(py_rules.chain_root_is_db_query_builder("select().filter_by"));
        assert!(py_rules.chain_root_is_db_query_builder("query().filter"));
        assert!(py_rules.chain_root_is_db_query_builder("Session.query().filter"));
        assert!(py_rules.chain_root_is_db_query_builder("select().join().where"));
        // Non-builder chain roots: must not match.
        assert!(!py_rules.chain_root_is_db_query_builder("w.Header().Get"));
        assert!(!py_rules.chain_root_is_db_query_builder("obj.foo().bar"));
        // Plain receiver chains (no intermediate call): not handled
        // here — the simple-chain branch covers them.
        assert!(!py_rules.chain_root_is_db_query_builder("repo.Find"));
        assert!(!py_rules.chain_root_is_db_query_builder("Project.objects.filter"));
        // Classification: chained-call DB-builder shapes anchor to
        // DbCrossTenantRead / DbMutation when the trailing verb matches.
        assert_eq!(
            py_rules.classify_sink_class("select().filter_by", &empty),
            Some(SinkClass::DbCrossTenantRead)
        );
        assert_eq!(
            py_rules.classify_sink_class("query().delete", &empty),
            Some(SinkClass::DbMutation)
        );
        assert_eq!(
            py_rules.classify_sink_class("select().update", &empty),
            Some(SinkClass::DbMutation)
        );
        // Regression guard: chained-call shapes that are NOT DB
        // builders (Go HTTP `w.Header().get`, generic `obj.foo().bar`)
        // remain suppressed even when the trailing verb prefix-matches.
        // Run on a Python-rules instance with the verb in its read
        // indicator vocabulary to exercise the guard.
        assert_eq!(py_rules.classify_sink_class("w.Header().get", &empty), None);
        assert_eq!(py_rules.classify_sink_class("obj.foo().get", &empty), None);

        // Languages without `db_query_builder_roots` defaults must not
        // false-positive on chained-call shapes.
        for lang in ["javascript", "typescript", "go", "java", "ruby", "rust"] {
            let rules = build_auth_rules(&Config::default(), lang);
            assert!(
                !rules.chain_root_is_db_query_builder("select().filter_by"),
                "lang={lang} unexpectedly classified select().filter_by as DB-builder chain",
            );
            assert_eq!(
                rules.classify_sink_class("select().filter_by", &empty),
                None,
                "lang={lang} unexpectedly classified select().filter_by as DB sink",
            );
        }
    }

    #[test]
    fn receiver_is_simple_chain_classifies_correctly() {
        use super::receiver_is_simple_chain;
        // Simple receiver chain (allowed for verb fallback).
        assert!(receiver_is_simple_chain("repo.Find"));
        assert!(receiver_is_simple_chain("Project.objects.filter"));
        assert!(receiver_is_simple_chain("self.cache.insert"));
        // Bare-identifier callee (rejected — no receiver evidence).
        assert!(!receiver_is_simple_chain("list"));
        assert!(!receiver_is_simple_chain("filter"));
        assert!(!receiver_is_simple_chain("create_audit_entry"));
        // Chained-call receiver (rejected — receiver type opaque).
        assert!(!receiver_is_simple_chain("w.Header().Get"));
        assert!(!receiver_is_simple_chain("db.Tx(opts).Query"));
    }

    #[test]
    fn sink_class_is_auth_relevant_only_for_non_local_classes() {
        use crate::auth_analysis::model::SinkClass;
        assert!(SinkClass::DbMutation.is_auth_relevant());
        assert!(SinkClass::DbCrossTenantRead.is_auth_relevant());
        assert!(SinkClass::RealtimePublish.is_auth_relevant());
        assert!(SinkClass::OutboundNetwork.is_auth_relevant());
        assert!(SinkClass::CacheCrossTenant.is_auth_relevant());
        assert!(!SinkClass::InMemoryLocal.is_auth_relevant());
    }

    /// Pin the JS DOM-globals / DOM-methods allowlist that closes the
    /// real-repo FP cluster of `document.getElementById` /
    /// `el.addEventListener` shapes prefix-matching read/mutation
    /// indicators (`get`, `add`).
    #[test]
    fn js_dom_globals_and_methods_classify_as_in_memory_local() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "javascript");
        let empty: HashSet<String> = HashSet::new();

        // Globals, receiver-first-segment match.
        assert_eq!(
            rules.classify_sink_class("document.getElementById", &empty),
            Some(SinkClass::InMemoryLocal)
        );
        assert_eq!(
            rules.classify_sink_class("window.scrollTo", &empty),
            Some(SinkClass::InMemoryLocal)
        );
        assert_eq!(
            rules.classify_sink_class("localStorage.getItem", &empty),
            Some(SinkClass::InMemoryLocal)
        );
        assert_eq!(
            rules.classify_sink_class("Math.random", &empty),
            Some(SinkClass::InMemoryLocal)
        );

        // Method allowlist, last-segment match regardless of receiver.
        assert_eq!(
            rules.classify_sink_class("input.addEventListener", &empty),
            Some(SinkClass::InMemoryLocal)
        );
        assert_eq!(
            rules.classify_sink_class("dropdown.appendChild", &empty),
            Some(SinkClass::InMemoryLocal)
        );
        assert_eq!(
            rules.classify_sink_class("el.querySelector", &empty),
            Some(SinkClass::InMemoryLocal)
        );

        // Real data-layer reads/mutations on plausible names still
        // classify (no over-suppression): `db.find_by_id` reads,
        // `repo.save` mutates.
        assert_eq!(
            rules.classify_sink_class("UserRepo.findById", &empty),
            Some(SinkClass::DbCrossTenantRead)
        );
        assert_eq!(
            rules.classify_sink_class("repo.update", &empty),
            Some(SinkClass::DbMutation)
        );
    }

    /// Pin the Python non-sink container recogniser.  Both type
    /// annotations (`x: set[int]`, `m: dict[str, int]`) and
    /// bare-callee constructor calls (`set()`, `dict()`,
    /// `defaultdict()`) must register the bound variable as a
    /// non-sink receiver, suppressing later `.update(..)` /
    /// `.add(..)` calls from classifying as `DbMutation` /
    /// `DbCrossTenantRead`.
    #[test]
    fn python_non_sink_container_recognition() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "python");

        // Type annotations: PEP 585 builtin generics + typing aliases.
        assert!(rules.is_non_sink_receiver_type("set"));
        assert!(rules.is_non_sink_receiver_type("set[int]"));
        assert!(rules.is_non_sink_receiver_type("dict[str, int]"));
        assert!(rules.is_non_sink_receiver_type("list[str]"));
        assert!(rules.is_non_sink_receiver_type("defaultdict"));
        assert!(rules.is_non_sink_receiver_type("Counter"));
        assert!(rules.is_non_sink_receiver_type("OrderedDict"));
        // Negative: arbitrary type names must not match.
        assert!(!rules.is_non_sink_receiver_type("Project"));
        assert!(!rules.is_non_sink_receiver_type("QuerySet"));

        // Bare-callee constructor form: `set()`, `dict()`,
        // `defaultdict()`, `Counter()`.
        assert!(rules.is_non_sink_constructor_callee("set"));
        assert!(rules.is_non_sink_constructor_callee("dict"));
        assert!(rules.is_non_sink_constructor_callee("list"));
        assert!(rules.is_non_sink_constructor_callee("frozenset"));
        assert!(rules.is_non_sink_constructor_callee("defaultdict"));
        assert!(rules.is_non_sink_constructor_callee("Counter"));
        // Negative: bare callees that are NOT non-sink types must not
        // be treated as constructors.  `update`, `filter`, `find` are
        // verb names, not container types.
        assert!(!rules.is_non_sink_constructor_callee("update"));
        assert!(!rules.is_non_sink_constructor_callee("filter"));
        assert!(!rules.is_non_sink_constructor_callee("find"));
        assert!(!rules.is_non_sink_constructor_callee("Project"));

        // End-to-end classification: `verified_ids.update(..)` with
        // `verified_ids` registered as a non-sink var classifies as
        // `InMemoryLocal`, the precondition for suppressing the
        // false `DbMutation` finding.
        let mut non_sink_vars: HashSet<String> = HashSet::new();
        non_sink_vars.insert("verified_ids".to_string());
        non_sink_vars.insert("requested_teams".to_string());
        assert_eq!(
            rules.classify_sink_class("verified_ids.update", &non_sink_vars),
            Some(SinkClass::InMemoryLocal)
        );
        assert_eq!(
            rules.classify_sink_class("requested_teams.add", &non_sink_vars),
            Some(SinkClass::InMemoryLocal)
        );
        // Recall guard: a real ORM mutation on the same verb still
        // classifies as `DbMutation` when the receiver is qualified.
        let empty: HashSet<String> = HashSet::new();
        assert_eq!(
            rules.classify_sink_class("Project.objects.update", &empty),
            Some(SinkClass::DbMutation)
        );
    }

    /// Cross-language recall guard: only Python populates the new
    /// container types by default.  Other-language defaults must
    /// not inadvertently inherit `set` / `dict` / `list` as non-sink
    /// types via the merge path (those names overlap with verb
    /// indicators in those languages).
    #[test]
    fn python_container_types_do_not_leak_to_other_languages() {
        let cfg = Config::default();
        for lang in ["javascript", "typescript", "go", "java", "ruby", "rust"] {
            let rules = build_auth_rules(&cfg, lang);
            assert!(
                !rules.is_non_sink_receiver_type("set"),
                "lang={lang} unexpectedly recognises bare `set` as non-sink type",
            );
            assert!(
                !rules.is_non_sink_receiver_type("dict"),
                "lang={lang} unexpectedly recognises bare `dict` as non-sink type",
            );
            assert!(
                !rules.is_non_sink_receiver_type("list"),
                "lang={lang} unexpectedly recognises bare `list` as non-sink type",
            );
        }
    }

    /// `require_<resource>_<role>` structural recogniser for project
    /// helpers like `require_trip_member`, `require_doc_owner`.
    #[test]
    fn is_authorization_check_recognises_require_resource_role_shapes() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");

        assert!(rules.is_authorization_check("require_trip_member"));
        assert!(rules.is_authorization_check("require_doc_owner"));
        assert!(rules.is_authorization_check("require_project_admin"));
        assert!(rules.is_authorization_check("ensure_workspace_access"));
        assert!(rules.is_authorization_check("authz::require_trip_member"));
        assert!(rules.is_authorization_check("self.require_album_editor"));

        // Negatives, random `require_*` calls without a known role
        // suffix do NOT count as authorization.
        assert!(!rules.is_authorization_check("require_db"));
        assert!(!rules.is_authorization_check("require_user"));
        assert!(!rules.is_authorization_check("require_login"));
        // Bare `require_member` / `require_owner` (no resource segment)
        // aren't enough, the resource segment is what makes the helper
        // unambiguous.
        assert!(!rules.is_authorization_check("require_member"));
        assert!(!rules.is_authorization_check("require_owner"));
    }

    /// Broader verb / role / context-suffix shapes seen in real-world
    /// Rust apps.  `check_<resource>_<role>_action` is the canonical
    /// lemmy idiom; the `is_<role>` predicate recogniser closes
    /// `is_mod_or_admin` style checks.
    #[test]
    fn is_authorization_check_recognises_check_action_and_predicate_shapes() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");

        // `check_<resource>_<role>_action` (lemmy `check_community_*_action`)
        assert!(rules.is_authorization_check("check_community_user_action"));
        assert!(rules.is_authorization_check("check_community_mod_action"));
        assert!(rules.is_authorization_check("check_community_admin_action"));
        assert!(rules.is_authorization_check("check_post_owner_action"));
        // Verb variants
        assert!(rules.is_authorization_check("assert_post_owner"));
        assert!(rules.is_authorization_check("verify_doc_editor"));
        // `_allowed` / `_valid` context suffix wrapping the role
        assert!(rules.is_authorization_check("require_trip_member_allowed"));
        assert!(rules.is_authorization_check("ensure_doc_owner_valid"));
        // Path-namespaced
        assert!(rules.is_authorization_check("authz::check_community_user_action"));
        assert!(rules.is_authorization_check("self.check_community_mod_action"));

        // `is_<role>` and `is_<role>_(or|and)_<role>` predicates.
        assert!(rules.is_authorization_check("is_admin"));
        assert!(rules.is_authorization_check("is_owner"));
        assert!(rules.is_authorization_check("is_member"));
        assert!(rules.is_authorization_check("is_moderator"));
        assert!(rules.is_authorization_check("is_mod_or_admin"));
        assert!(rules.is_authorization_check("is_owner_or_admin"));
        assert!(rules.is_authorization_check("is_admin_or_moderator"));
        assert!(rules.is_authorization_check("is_member_and_owner"));

        // Negatives, predicates whose tokens are NOT known auth roles.
        assert!(!rules.is_authorization_check("is_user"));
        assert!(!rules.is_authorization_check("is_logged_in"));
        assert!(!rules.is_authorization_check("is_active"));
        assert!(!rules.is_authorization_check("is_visible"));
        assert!(!rules.is_authorization_check("is_admin_or_logged_in"));
        // `_action` / `_allowed` / `_valid` suffix without preceding
        // role still rejects.
        assert!(!rules.is_authorization_check("check_db_action"));
        assert!(!rules.is_authorization_check("check_session_valid"));
    }

    /// Reference implementation of the pre-optimization allocating
    /// `matches_name` body — pins the zero-alloc `canon_has_prefix` stream
    /// against the original `canonical_name`-based comparison.
    fn legacy_matches_name(name: &str, pattern: &str) -> bool {
        use super::canonical_name;
        let name_last = name.rsplit('.').next().unwrap_or(name);
        let pattern_last = pattern.rsplit('.').next().unwrap_or(pattern);
        let name_norm = canonical_name(name_last);
        let pattern_norm = canonical_name(pattern_last);
        !pattern_norm.is_empty()
            && (name_norm == pattern_norm || name_norm.starts_with(&pattern_norm))
    }

    #[test]
    fn canon_stream_matches_name_equals_legacy_allocating_path() {
        use super::matches_name;
        // A matrix spanning: dotted receivers, case differences, digits,
        // separators/punctuation (filtered out by canonicalization),
        // non-ASCII (whole char dropped), empty pattern, prefix vs equal
        // vs mismatch, and pattern-longer-than-name.
        let names = [
            "",
            "get",
            "Get",
            "GET",
            "get_user",
            "getUser",
            "get.user",
            "user.repo.save",
            "Model.objects.filter",
            "require_trip_member",
            "is_mod_or_admin",
            "hasRole",
            "has-role",
            "has_role_",
            "PreAuthorize",
            "preauthorize",
            "café_check", // non-ASCII in the middle
            "naïveGuard",
            "db.Tx(opts).Query",
            "12345",
            "a1b2c3",
            "___", // canonical form empty
            "...",
            "checkOwnership",
            "check_ownership",
        ];
        let patterns = [
            "",
            "get",
            "Get",
            "getuser",
            "get_user",
            "user",
            "save",
            "filter",
            "PreAuthorize",
            "preauthorize",
            "pre",
            "hasRole",
            "has_role",
            "member",
            "require_trip_member",
            "is_mod_or_admin",
            "café",
            "naive",
            "query",
            "123",
            "a1b2c3d4", // longer than some names
            "___",      // canonical empty pattern → never matches
            "ownership",
            "checkOwnership",
        ];
        for n in names {
            for p in patterns {
                assert_eq!(
                    matches_name(n, p),
                    legacy_matches_name(n, p),
                    "matches_name(&{n:?}, &{p:?}) diverged from legacy allocating path",
                );
            }
        }
    }
}
