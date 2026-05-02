use super::config::AuthAnalysisRules;
use super::model::{
    AnalysisUnit, AnalysisUnitKind, AuthCheck, AuthCheckKind, AuthorizationModel, OperationKind,
    SensitiveOperation, ValueRef, ValueSourceKind,
};
use crate::patterns::Severity;

#[derive(Debug, Clone)]
pub struct AuthFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub span: (usize, usize),
    pub message: String,
}

pub fn run_checks(model: &AuthorizationModel, rules: &AuthAnalysisRules) -> Vec<AuthFinding> {
    let mut findings = Vec::new();
    findings.extend(check_admin_routes(model, rules));
    findings.extend(check_ownership_gaps(model, rules));
    findings.extend(check_partial_batch_authorization(model, rules));
    findings.extend(check_stale_authorization(model, rules));
    findings.extend(check_token_override_without_validation(model, rules));
    findings.sort_by(|a, b| a.span.cmp(&b.span).then_with(|| a.rule_id.cmp(&b.rule_id)));
    findings.dedup_by(|a, b| a.span == b.span && a.rule_id == b.rule_id);
    findings
}

fn check_admin_routes(model: &AuthorizationModel, rules: &AuthAnalysisRules) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for route in &model.routes {
        let Some(unit) = model.units.get(route.unit_idx) else {
            continue;
        };
        let requires_admin =
            rules.requires_admin_path(&route.path) || route_is_admin_sensitive(unit);
        if !requires_admin {
            continue;
        }

        let has_admin = route
            .middleware_calls
            .iter()
            .any(|mw| rules.is_admin_guard(&mw.name, &mw.args));
        let has_login = route
            .middleware_calls
            .iter()
            .any(|mw| rules.is_login_guard(&mw.name) || rules.is_admin_guard(&mw.name, &mw.args));

        if !has_admin && has_login {
            findings.push(AuthFinding {
                rule_id: rules.rule_id("admin_route_missing_admin_check"),
                severity: Severity::High,
                span: route.handler_span,
                message: format!(
                    "route `{}` appears admin-sensitive but its middleware only enforces login-level access",
                    route.path
                ),
            });
        }
    }

    findings
}

fn check_ownership_gaps(model: &AuthorizationModel, rules: &AuthAnalysisRules) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        if !unit_has_user_input_evidence(unit) {
            continue;
        }
        for op in &unit.operations {
            if op.kind == OperationKind::TokenLookup {
                continue;
            }
            // `InMemoryLocal` sinks (HashMap/HashSet/Vec/… local
            // bookkeeping) are never authorization-relevant.
            if op.sink_class.is_some_and(|c| !c.is_auth_relevant()) {
                continue;
            }
            if op.kind == OperationKind::Read && unit_is_auth_helper(unit) {
                continue;
            }
            let relevant_subjects: Vec<&ValueRef> = op
                .subjects
                .iter()
                .filter(|s| is_relevant_target_subject(s, unit))
                .collect();
            if relevant_subjects.is_empty() {
                continue;
            }
            if op.kind == OperationKind::Read || op.kind == OperationKind::Mutation {
                if is_delegated_read_with_actor_context(unit, op, &relevant_subjects) {
                    continue;
                }
                if !has_prior_subject_auth(unit, op, &relevant_subjects) {
                    findings.push(AuthFinding {
                        rule_id: rules.rule_id("missing_ownership_check"),
                        severity: Severity::High,
                        span: op.span,
                        message: format!(
                            "operation `{}` uses scoped identifier input without a preceding ownership or membership check",
                            op.callee
                        ),
                    });
                }
            }
        }
    }

    findings
}

fn check_partial_batch_authorization(
    model: &AuthorizationModel,
    rules: &AuthAnalysisRules,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        if !unit_has_user_input_evidence(unit) {
            continue;
        }
        for op in &unit.operations {
            // In-memory bookkeeping is never a batch sink.
            if op.sink_class.is_some_and(|c| !c.is_auth_relevant()) {
                continue;
            }
            let batch_subjects: Vec<&ValueRef> = op
                .subjects
                .iter()
                .filter(|subject| is_batch_collection(subject))
                .collect();
            if batch_subjects.is_empty() {
                continue;
            }

            let partial_check = unit.auth_checks.iter().any(|check| {
                check.line <= op.line
                    && check.subjects.iter().any(|subject| {
                        subject.source_kind == ValueSourceKind::ArrayIndex
                            && subject.base.as_ref().is_some_and(|base| {
                                batch_subjects
                                    .iter()
                                    .any(|op_subject| op_subject.name == *base)
                            })
                    })
            });
            let full_collection_check = has_prior_collection_auth(unit, op, &batch_subjects);

            if partial_check && !full_collection_check {
                findings.push(AuthFinding {
                    rule_id: rules.rule_id("partial_batch_authorization"),
                    severity: Severity::High,
                    span: op.span,
                    message: format!(
                        "batch operation `{}` authorizes only a single indexed element before acting on the full collection",
                        op.callee
                    ),
                });
            }
        }
    }

    findings
}

fn check_stale_authorization(
    model: &AuthorizationModel,
    rules: &AuthAnalysisRules,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        if !unit_has_user_input_evidence(unit) {
            continue;
        }
        for op in unit.operations.iter().filter(|operation| {
            operation.kind == OperationKind::Mutation
                && operation.sink_class.is_none_or(|c| c.is_auth_relevant())
        }) {
            let session_subject = op.subjects.iter().any(is_stale_session_subject);
            if !session_subject {
                continue;
            }

            let has_fresh_auth = unit.auth_checks.iter().any(|check| {
                check.line <= op.line
                    && matches!(
                        check.kind,
                        AuthCheckKind::Ownership
                            | AuthCheckKind::Membership
                            | AuthCheckKind::AdminGuard
                            | AuthCheckKind::Other
                    )
            });

            if !has_fresh_auth {
                findings.push(AuthFinding {
                    rule_id: rules.rule_id("stale_authorization"),
                    severity: Severity::Medium,
                    span: op.span,
                    message: format!(
                        "mutation `{}` relies on session-carried state without a fresh authorization check",
                        op.callee
                    ),
                });
            }
        }
    }

    findings
}

fn check_token_override_without_validation(
    model: &AuthorizationModel,
    rules: &AuthAnalysisRules,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        // The rule reasons about "Token acceptance flow", by
        // construction, that is a user-facing handler that receives a
        // token from the client and writes through token-bound state.
        // Internal helpers, Celery / cron tasks, Django migrations,
        // pytest fixtures, and seed-data utilities have no user reach
        // and cannot host a token-acceptance flow even when their
        // call shape happens to look token-y (`account.token = …;
        // account.save()`).  Gate on positive user-input evidence so
        // these pure backend units are never claimed as a token flow.
        if !unit_has_user_input_evidence(unit) {
            continue;
        }
        let Some(token_lookup) = unit
            .operations
            .iter()
            .find(|operation| operation.kind == OperationKind::TokenLookup)
        else {
            continue;
        };
        let Some(final_write) = unit.operations.iter().rev().find(|operation| {
            operation.kind == OperationKind::Mutation && operation.line >= token_lookup.line
        }) else {
            continue;
        };

        let override_pattern = (final_write.text.contains("||")
            || final_write
                .text
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .any(|segment| segment.eq_ignore_ascii_case("or")))
            && final_write
                .subjects
                .iter()
                .any(|subject| subject.source_kind == ValueSourceKind::TokenField)
            && final_write
                .subjects
                .iter()
                .any(|subject| subject.source_kind != ValueSourceKind::TokenField);
        let has_expiry_check = unit
            .auth_checks
            .iter()
            .any(|check| check.kind == AuthCheckKind::TokenExpiry)
            || unit
                .condition_texts
                .iter()
                .any(|condition| rules.has_expiry_field(condition));
        let has_recipient_check = unit
            .auth_checks
            .iter()
            .any(|check| check.kind == AuthCheckKind::TokenRecipient)
            || unit
                .condition_texts
                .iter()
                .any(|condition| rules.has_recipient_field(condition));

        if override_pattern || !has_expiry_check || !has_recipient_check {
            let mut missing = Vec::new();
            if override_pattern {
                missing.push("request data overrides token-bound values");
            }
            if !has_expiry_check {
                missing.push("token expiration is not validated");
            }
            if !has_recipient_check {
                missing.push("token recipient identity is not validated");
            }
            findings.push(AuthFinding {
                rule_id: rules.rule_id("token_override_without_validation"),
                severity: Severity::High,
                span: final_write.span,
                message: format!(
                    "token acceptance flow writes through `{}` without validating that {}",
                    final_write.callee,
                    missing.join(", ")
                ),
            });
        }
    }

    findings
}

fn route_is_admin_sensitive(unit: &AnalysisUnit) -> bool {
    unit.call_sites.iter().any(|call| {
        let lower = call.name.to_ascii_lowercase();
        lower.contains("admin") || lower.contains("impersonat") || lower.contains("role")
    })
}

fn has_prior_subject_auth(
    unit: &AnalysisUnit,
    op: &SensitiveOperation,
    subjects: &[&ValueRef],
) -> bool {
    if has_row_fetch_exemption(unit, op) {
        return true;
    }

    let relevant_checks = unit.auth_checks.iter().filter(|check| {
        check.line <= op.line
            && !matches!(
                check.kind,
                AuthCheckKind::LoginGuard
                    | AuthCheckKind::TokenExpiry
                    | AuthCheckKind::TokenRecipient
            )
    });

    relevant_checks.into_iter().any(|check| {
        subjects
            .iter()
            .any(|subject| auth_check_covers_subject(check, subject, unit))
    })
}

/// Row-fetch exemption.
///
/// Recognises the "fetch-then-authorize" idiom: a handler fetches a
/// row by id then calls a named authorization function on it. The
/// check appears textually after the fetch, so the
/// `check.line <= op.line` rule cannot cover the fetch.
///
/// The exemption fires only when:
/// 1. `op` is the row-fetch operation itself (line == row let-line).
/// 2. SOME auth check in the unit names the resulting row variable as
///    a subject (directly or via `check.subjects[i].base`).
///
/// Coverage is intentionally narrow: only the row-fetch operation is
/// exempted.  Any sink that runs *between* the fetch and the check
/// (e.g. `delete(community)` before `check_*`) still flags, because
/// its subject is `community` itself, not a fetch arg, and we
/// require the operation to be a row-fetch site to apply the
/// exemption.
fn has_row_fetch_exemption(unit: &AnalysisUnit, op: &SensitiveOperation) -> bool {
    // Find the row var (if any) declared at this op's line.
    let row_var: Option<&str> = unit
        .row_population_data
        .iter()
        .find_map(|(var, (line, _))| {
            if *line == op.line {
                Some(var.as_str())
            } else {
                None
            }
        });
    let Some(row_var) = row_var else {
        return false;
    };

    // Look for any non-login auth check whose subjects mention the row.
    // Match against the *root* of the subject's chain (`a.b.c` → `a`)
    // so an auth check on a row's nested field, e.g.
    // `is_mod_or_admin(pool, &user, comment_view.community.id)` ,
    // still names the row var.
    unit.auth_checks.iter().any(|check| {
        if matches!(
            check.kind,
            AuthCheckKind::LoginGuard | AuthCheckKind::TokenExpiry | AuthCheckKind::TokenRecipient
        ) {
            return false;
        }
        check
            .subjects
            .iter()
            .any(|subj| chain_root(subj) == row_var)
    })
}

/// Root segment of a subject's chain.  Subjects produced from
/// `a.b.c` carry `name = "a.b.c"` and `base = Some("a.b")`; the root
/// is `a`.  Bare identifiers carry `base = None` and use `name`.
fn chain_root(subj: &ValueRef) -> &str {
    let raw = subj.base.as_deref().unwrap_or(subj.name.as_str());
    raw.split('.').next().unwrap_or(raw)
}

fn has_prior_collection_auth(
    unit: &AnalysisUnit,
    op: &SensitiveOperation,
    subjects: &[&ValueRef],
) -> bool {
    let relevant_checks = unit.auth_checks.iter().filter(|check| {
        check.line <= op.line
            && !matches!(
                check.kind,
                AuthCheckKind::LoginGuard
                    | AuthCheckKind::TokenExpiry
                    | AuthCheckKind::TokenRecipient
            )
    });

    relevant_checks.into_iter().any(|check| {
        subjects.iter().any(|subject| {
            check.subjects.iter().any(|check_subject| {
                check_subject.source_kind != ValueSourceKind::ArrayIndex
                    && canonical_subject_name(check_subject) == subject.name
            })
        })
    })
}

fn auth_check_covers_subject(check: &AuthCheck, subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    // **Route-level guard short-circuit.**
    //
    // A check declared at the route boundary (Flask `@requires_role`,
    // FastAPI `dependencies=[Depends(requires_access_dag(method=
    // "POST", access_entity=DagAccessEntity.RUN))]`, Django
    // `@permission_required`, Spring `@PreAuthorize`, Rails
    // `before_action :authorize`, axum `RequireAuthorizationLayer`)
    // gates the entire handler.  The decorator / dependency call is
    // opaque to the engine, the inner `requires_access_dag` carries
    // no per-arg `ValueRef` pointing back into the handler body, so
    // the per-name subject coverage walk below cannot match it.  The
    // structural shape, however, is unambiguous: every value the
    // handler receives, every row it fetches, and every sink it
    // calls runs after the route-level check has decided
    // authorization.
    //
    // `has_prior_subject_auth` already filters out
    // `LoginGuard` / `TokenExpiry` / `TokenRecipient` kinds before
    // calling this helper (login alone proves identity, not
    // authorization), so by the time we land here the kind is
    // `Other` / `Membership` / `Ownership` / `AdminGuard`, i.e. an
    // authorization-bearing decorator-level check.  Returning `true`
    // unconditionally for those is the correct semantics.
    if check.is_route_level {
        return true;
    }
    let subject_key = canonical_subject_name(subject);
    let subject_related_base = related_subject_base(subject);
    // A2 + B3: walk the row-binding chain from this subject so a
    // check subject naming any ancestor row covers downstream column
    // reads.  E.g. `group_id → row → rows`: a check on `rows` (the
    // SQL-authorized result var) covers the subject `group_id`.
    let subject_row_chain = row_binding_chain(unit, &subject.name);
    // B3: if any ancestor row is in the SQL-authorized set, every
    // ownership check materially covers this subject.  We model this
    // by treating the SQL synth check as covering whatever subject
    // names share an ancestor in `authorized_sql_vars`.
    let subject_anchor_authorized = subject_row_chain
        .iter()
        .any(|name| unit.authorized_sql_vars.contains(name));

    // **Row-population reverse-walk** (lemmy fetch-then-check pattern).
    //
    // `row_population_data[R]` records the value-refs of every arg
    // passed to a `let R = CALL(args)` row fetch.  When a later auth
    // check authorizes the resulting row (e.g. `check_community_user_action(
    // &user, &community, ..)` after `let community = Community::read(
    // pool, data.community_id)`), the check materially covers
    // `data.community_id` too, it gated access to the row that was
    // fetched using that id, so any subsequent operation re-using the
    // same id (read of a related view, mutation on the row itself) is
    // within the scope of that authorization.
    //
    // Match by canonical subject name so `data.community_id`,
    // `community_id`, `data.comment_id`, etc. all resolve uniformly
    // regardless of whether the route handler aliased the request
    // field into a local before passing it on.
    //
    // **Local-alias chain.**  When the subject is a plain identifier
    // (no base/field), also consult `unit.var_alias_chain`: a sink
    // that uses `community_id` after `let community_id =
    // req.community_id` should see the population args recorded as
    // `req.community_id` matched, not just the bare name.
    let subject_alias_chain: Option<&str> = if subject.base.is_none() && subject.field.is_none() {
        unit.var_alias_chain.get(&subject.name).map(|s| s.as_str())
    } else {
        None
    };
    let subject_populates: Vec<&str> = unit
        .row_population_data
        .iter()
        .filter_map(|(row_var, (_line, args))| {
            let matches_arg = args.iter().any(|arg| {
                if canonical_subject_name(arg) == subject_key {
                    return true;
                }
                if let Some(chain) = subject_alias_chain
                    && arg.name == chain
                {
                    return true;
                }
                false
            });
            if matches_arg {
                Some(row_var.as_str())
            } else {
                None
            }
        })
        .collect();

    check.subjects.iter().any(|check_subject| {
        let check_key = canonical_subject_name(check_subject);
        let check_related_base = related_subject_base(check_subject);
        if check_key == subject_key
            || (subject_related_base.is_some() && subject_related_base == check_related_base)
            || (subject_related_base.as_ref() == Some(&check_key))
            || (check_related_base.as_ref() == Some(&subject_key))
        {
            return true;
        }
        for row in &subject_row_chain {
            if check_key == *row || check_related_base.as_deref() == Some(row.as_str()) {
                return true;
            }
        }
        // Row-population reverse-walk: subject was passed to a row
        // fetch, and the check covers that row (chain root match on
        // the row var).
        for row in &subject_populates {
            if chain_root(check_subject) == *row {
                return true;
            }
        }
        // B3: SQL synth checks name the auth-gated row var directly.
        // If our subject's row chain leads into the same authorized
        // var family this check anchors to, accept the coverage.
        if subject_anchor_authorized && unit.authorized_sql_vars.contains(&check_key) {
            return true;
        }
        false
    })
}

/// Walk `unit.row_field_vars` transitively from `start` (inclusive)
/// to recover every ancestor row binding name.  Cycle-safe via a
/// visited set; depth-bounded at 16 hops to keep the worst case
/// trivial.  Returns a vec containing `start` followed by each
/// ancestor, empty when `start` is empty.
fn row_binding_chain(unit: &AnalysisUnit, start: &str) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    if start.is_empty() {
        return chain;
    }
    let mut cur = start.to_string();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut hops = 0;
    while hops < 16 && seen.insert(cur.clone()) {
        chain.push(cur.clone());
        let Some(next) = unit.row_field_vars.get(&cur) else {
            break;
        };
        cur = next.clone();
        hops += 1;
    }
    chain
}

fn canonical_subject_name(subject: &ValueRef) -> String {
    match subject.source_kind {
        ValueSourceKind::ArrayIndex => subject.base.clone().unwrap_or_else(|| subject.name.clone()),
        _ => subject.name.clone(),
    }
}

fn related_subject_base(subject: &ValueRef) -> Option<String> {
    let base = subject.base.as_deref()?;
    let lower = base.to_ascii_lowercase();
    if lower == "req"
        || lower.starts_with("req.")
        || lower == "request"
        || lower.starts_with("request.")
        || lower == "ctx"
        || lower.starts_with("ctx.")
        || lower == "session"
        || lower.starts_with("session.")
    {
        None
    } else {
        Some(base.to_string())
    }
}

fn is_relevant_target_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    is_id_like(subject)
        && !is_actor_context_subject(subject, unit)
        && !is_const_bound_subject(subject, unit)
        && !is_typed_bounded_subject(subject, unit)
        && !is_caller_scope_entity_subject(subject, unit)
}

/// True iff `subject` is a member-access of form `<entity>.id` /
/// `<entity>.pk` whose root identifier is a unit parameter named after
/// a scope-bearing domain entity (`organization`, `project`, `team`,
/// `workspace`, `tenant`, `account`, `community`, `repository`, …).
///
/// Such subjects are the *scope* of the operation — the ownership
/// constraint the caller passed in — not a user-controlled target.
/// Helpers like
/// `def get_environments(request, organization: Organization): …
///  Environment.objects.filter(organization_id=organization.id, …)`
/// inherit the caller's authorization on the entity object; the call
/// itself enforces tenant scoping.  Without this exemption, every
/// internal helper in a multi-tenant Django/Rails/Laravel codebase
/// flags `missing_ownership_check` because the engine cannot tell
/// "scoping arg" from "user-targeted arg".
///
/// Conservative scope:
/// * Field must be `id` or `pk` (the canonical primary-key fields).
///   `entity.name` / `entity.slug` are deliberately excluded — those
///   could be user-supplied display strings even on a typed entity.
/// * Root must be exactly a unit parameter (not a derived local).
/// * Root name must be in the scope-entity vocabulary.  Names like
///   `user`, `member`, `actor` are deliberately omitted: those carry
///   actor semantics and are handled separately by
///   `is_actor_context_subject`.
fn is_caller_scope_entity_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    let Some(field) = subject.field.as_deref() else {
        return false;
    };
    let field_lower = field.to_ascii_lowercase();
    if !matches!(field_lower.as_str(), "id" | "pk") {
        return false;
    }
    let Some(base) = subject.base.as_deref() else {
        return false;
    };
    let root = base.split('.').next().unwrap_or(base);
    if !is_caller_scope_entity_name(root) {
        return false;
    }
    unit.params.iter().any(|p| p == root)
}

/// Recognises parameter names that conventionally carry a *scope*
/// entity — the multi-tenant ownership boundary inherited from the
/// caller — rather than a user-controlled target identifier.  Used
/// only by `is_caller_scope_entity_subject` to suppress
/// `missing_ownership_check` on `<entity>.id` arguments to ORM /
/// query / mutation calls.
///
/// Vocabulary matches the canonical multi-tenant primitives across
/// Django (Sentry, Saleor), Rails (Discourse, Mastodon), and Laravel
/// /  Symfony idioms.  Both singular and short forms are matched
/// (`organization` / `org`, `repository` / `repo`).  Excluded:
/// `user`, `member`, `actor` (actor semantics, covered by
/// `is_actor_context_subject` and per-actor self-id detectors).
fn is_caller_scope_entity_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "organization"
            | "org"
            | "project"
            | "team"
            | "workspace"
            | "tenant"
            | "account"
            | "community"
            | "group"
            | "repository"
            | "repo"
            | "company"
    )
}

/// True iff `subject` is a plain identifier whose declaration binds
/// it to a literal constant (`id := "id"`, `let userId = 1`, etc.).
/// Such bindings cannot be user-controlled and so must not be
/// classified as scoped-identifier subjects.  Only matches plain
/// `Identifier`-kind subjects (no base/field), member chains like
/// `req.params.id` still pass through to the regular checks.
fn is_const_bound_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    if subject.base.is_some() || subject.field.is_some() {
        return false;
    }
    unit.const_bound_vars.contains(&subject.name)
}

/// True iff `subject` is a plain identifier that resolves to a
/// function parameter whose static type is a payload-incompatible
/// scalar (numeric or boolean, see [`super::apply_typed_bounded_params`]).
/// Spring `@PathVariable Long userId`, Axum `Path<i64>`, NestJS
/// `@Param('id') id: number`, and FastAPI `user_id: int` all qualify.
///
/// also matches member-access subjects like `dto.userId`
/// when `dto` is a typed-extractor parameter recognised by a Phase
/// 1-2 matcher AND the field's declared TypeKind is Int/Bool.
fn is_typed_bounded_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    if subject.base.is_none() && subject.field.is_none() {
        return unit.typed_bounded_vars.contains(&subject.name);
    }
    // member-access shape `base.field` whose `base` is a
    // typed-extractor parameter and whose field is declared as an
    // Int/Bool in the same-file DTO definition.  Per Hard Rule 3,
    // only fires when the base param itself was recognised by a
    // typed-extractor matcher, bare `dto.age` without a framework gate
    // never lifts.
    let Some(base) = subject.base.as_deref() else {
        return false;
    };
    let Some(field) = subject.field.as_deref() else {
        return false;
    };
    let root = base.split('.').next().unwrap_or(base);
    unit.typed_bounded_dto_fields
        .get(root)
        .is_some_and(|fields| fields.iter().any(|f| f == field))
}

fn is_actor_context_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    if is_self_scoped_session_subject(subject) {
        return true;
    }

    // Per-unit dynamic session-base set (TRPC `Options { ctx: { user:
    // TrpcSessionUser } }` populates `<localCtx>.user` via the
    // typed-extractor pre-pass).  The static `is_self_scoped_session_base`
    // list deliberately omits bare `ctx.user` because `ctx` is generic
    // and a blanket addition over-suppresses in non-TRPC code; this
    // branch fires only when the param's static type literally
    // references `TrpcSessionUser` (or a known TRPC alias).
    if let Some(base) = subject.base.as_deref()
        && unit.self_scoped_session_bases.contains(base)
        && subject.field.as_deref().is_some_and(is_self_actor_id_field)
    {
        return true;
    }

    // A3: `V.id`-shape subjects where `V` is bound from a login-guard /
    // auth-check call (or from a typed self-actor extractor parameter)
    // are the caller's own id. `V.group_id` / `V.workspace_id` stay
    // relevant, only self-identifier fields trip this branch, so
    // foreign scoped ids on the same actor binding still flag.
    if let Some(base) = subject.base.as_deref() {
        let root = base.split('.').next().unwrap_or(base);
        if unit.self_actor_vars.contains(root)
            && subject.field.as_deref().is_some_and(is_self_actor_id_field)
        {
            return true;
        }
    }

    // Transitive copy of `V.id`: `let uid = user.id; query(.., &[uid])`
    //, the subject `uid` is a plain identifier with no base/field, but
    // was recorded as a self-actor id copy at extract time.  Treat it
    // as actor context.
    if unit.self_actor_id_vars.contains(&subject.name) {
        return true;
    }

    matches!(
        subject_identity_key(subject).as_deref(),
        Some(
            "ownerid"
                | "authorid"
                | "actorid"
                | "currentuserid"
                | "uploaderid"
                | "createdby"
                | "updatedby"
        )
    )
}

fn is_self_actor_id_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "id" | "user_id" | "userid" | "uid"
            // Self-publish / self-channel fields: when the receiver
            // is bound from `require_auth(..)`, `user.email` /
            // `user.username` / `user.handle` reference the actor's
            // own identity (e.g. `realtime.publish_to_user(&user.email,
            // ...)` is a self-channel publish, not a foreign target).
            | "email" | "username" | "handle"
    )
}

fn subject_identity_key(subject: &ValueRef) -> Option<String> {
    let raw = match subject.source_kind {
        ValueSourceKind::ArrayIndex => subject.base.as_deref().unwrap_or(&subject.name),
        _ => subject
            .field
            .as_deref()
            .or(subject.base.as_deref())
            .unwrap_or(&subject.name),
    };
    let key: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if key.is_empty() { None } else { Some(key) }
}

fn is_self_scoped_session_subject(subject: &ValueRef) -> bool {
    subject.source_kind == ValueSourceKind::Session
        && subject
            .base
            .as_deref()
            .is_some_and(is_self_scoped_session_base)
}

fn is_self_scoped_session_base(base: &str) -> bool {
    matches!(
        base,
        "req.session.user"
            | "request.session.user"
            | "session.user"
            | "req.session.currentUser"
            | "request.session.currentUser"
            | "session.currentUser"
            | "req.user"
            | "request.user"
            | "req.currentUser"
            | "request.currentUser"
            | "ctx.session.user"
            | "ctx.session.currentUser"
            | "ctx.state.user"
            | "ctx.state.currentUser"
    )
}

fn is_stale_session_subject(subject: &ValueRef) -> bool {
    subject.source_kind == ValueSourceKind::Session
        && is_id_like(subject)
        && !is_self_scoped_session_subject(subject)
}

fn unit_is_auth_helper(unit: &AnalysisUnit) -> bool {
    let Some(name) = unit.name.as_deref() else {
        return false;
    };
    let normalized: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (normalized.starts_with("has")
        || normalized.starts_with("check")
        || normalized.starts_with("require")
        || normalized.starts_with("verify")
        || normalized.starts_with("authorize")
        || normalized.starts_with("can")
        || normalized.starts_with("is"))
        && (normalized.contains("membership")
            || normalized.contains("ownership")
            || normalized.contains("access")
            || normalized.contains("permission")
            || normalized.contains("authoriz"))
}

fn is_delegated_read_with_actor_context(
    unit: &AnalysisUnit,
    op: &SensitiveOperation,
    relevant_subjects: &[&ValueRef],
) -> bool {
    unit.kind == AnalysisUnitKind::RouteHandler
        && op.kind == OperationKind::Read
        && op.callee.to_ascii_lowercase().contains("service")
        && op.subjects.iter().any(is_self_scoped_session_subject)
        && relevant_subjects.iter().any(|subject| {
            matches!(
                subject.source_kind,
                ValueSourceKind::RequestParam
                    | ValueSourceKind::RequestBody
                    | ValueSourceKind::RequestQuery
            )
        })
}

fn is_id_like(subject: &ValueRef) -> bool {
    let field = subject
        .field
        .as_deref()
        .or(subject.base.as_deref())
        .unwrap_or(&subject.name);
    is_id_like_name(field)
}

/// String-level analogue of `is_id_like` for working with parameter
/// names (which carry no `ValueRef` structure).  Mirrors the same
/// suffix vocabulary so a parameter `doc_id` / `groupId` / `userIds`
/// is recognised as an id-bearing input.
fn is_id_like_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "id"
        || lower.ends_with("id")
        || lower.ends_with("_id")
        || lower.ends_with("ids")
        || lower.contains("workspaceid")
        || lower.contains("projectid")
        || lower.contains("noteid")
}

/// True when the analysis unit shows positive evidence of receiving
/// user-controlled input, the precondition for any auth rule that
/// reasons about "scoped identifier" or "token-acceptance flow"
/// shapes.
///
/// A unit qualifies if any of the following hold:
/// * It is a recognised framework route handler (`RouteHandler` ,
///   the strongest signal: registered with a router).
/// * It accesses a request-shaped value (`request.body`, `req.params`,
///   `c.Query(..)`, etc.), populated as `context_inputs`.
/// * It declares at least one parameter whose name signals an
///   externally-supplied value (id-like, token-like, request-like).
///   Internal helpers that take only typed objects
///   (`promotion: Promotion`, `apps`, `schema_editor`, `config`,
///   `items`) are excluded.
///
/// Migrations, Celery tasks, pytest fixtures, conftest hooks, and
/// pure utility helpers fail all three conditions and are skipped ,
/// they cannot, by construction, be the entry point of an
/// authentication-bearing flow.
fn unit_has_user_input_evidence(unit: &AnalysisUnit) -> bool {
    if unit.kind == AnalysisUnitKind::RouteHandler {
        return true;
    }
    if !unit.context_inputs.is_empty() {
        return true;
    }
    unit.params.iter().any(|p| is_external_input_param_name(p))
}

/// Parameter-name heuristic: does this name carry external/user input
/// as part of its calling contract?  Captures three classes of name:
///   * id-like (`*_id`, `*Id`, `id`, `*Ids`),
///   * token-like (`token`, `*_token`, `accessToken`),
///   * framework-request objects (`request`, `req`, `ctx`, the
///     standard names used by Express/Django/Flask/Gin/Axum/NestJS
///     handlers as the parameter that carries the HTTP request).
///
/// Used by `unit_has_user_input_evidence` to recognise helper
/// functions that, while not registered as route handlers, are
/// clearly invoked with caller-supplied identifiers or request data.
fn is_external_input_param_name(name: &str) -> bool {
    // Pytest / unittest.mock convention: parameters injected by
    // `@mock.patch(...)` decorators are universally named
    // `mock_<thing>` (`mock_project_id`, `mock_session`,
    // `mock_user_id`).  Their values are MagicMock instances created
    // by the test framework, not user-supplied input, even when the
    // suffix carries an id-shaped tail.  Refusing the entire `mock_`
    // prefix is structural (mirrors pytest's documented convention)
    // and closes the airflow `tests/unit/google/cloud/hooks/`
    // cluster where every test method takes
    // `(self, get_conn, mock_project_id)` and the suffix tripped the
    // id-like heuristic.
    if name.starts_with("mock_") || name.starts_with("mocked_") {
        return false;
    }
    if is_id_like_name(name) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    // Token-shaped: bare `token` or any `*_token` / `*Token` /
    // `accessToken` / `refreshToken`-style suffix.  Conservative ,
    // only fires on explicit token-naming, not on incidental
    // substrings.
    if lower == "token" || lower.ends_with("_token") || lower.ends_with("token") {
        return true;
    }
    // Standard framework request-parameter names.  These cover the
    // cross-language convention for the parameter holding the HTTP
    // request object (`req` / `request` / `ctx` / `context` / `info`)
    // **and** the typed-extractor parameter naming used by
    // Axum/Actix/NestJS handlers (`path`, `payload`, `body`, `dto`,
    // `form`, `query`).  In `web::Path<String>` / `web::Json<T>` /
    // `@Body() dto: ...` the parameter name itself is the standard
    // convention used by every example in the framework docs, so
    // matching on the name is a reliable proxy for the typed
    // extractor binding.  Bare `c` is too common (incidental local
    // variable) to include without an additional type signal.
    matches!(
        lower.as_str(),
        "req"
            | "request"
            | "ctx"
            | "context"
            | "info"
            | "path"
            | "payload"
            | "body"
            | "dto"
            | "form"
            | "query"
    )
}

fn is_batch_collection(subject: &ValueRef) -> bool {
    subject.source_kind == ValueSourceKind::Identifier
        && subject.name.to_ascii_lowercase().ends_with("ids")
}

#[cfg(test)]
mod tests {
    use super::{
        auth_check_covers_subject, is_actor_context_subject, is_caller_scope_entity_name,
        is_caller_scope_entity_subject, is_external_input_param_name, is_relevant_target_subject,
        unit_has_user_input_evidence,
    };
    use crate::auth_analysis::model::{AnalysisUnit, AnalysisUnitKind, ValueRef, ValueSourceKind};
    use std::collections::{HashMap, HashSet};

    fn empty_unit() -> AnalysisUnit {
        AnalysisUnit {
            kind: AnalysisUnitKind::Function,
            name: Some("handle".into()),
            span: (0, 0),
            params: Vec::new(),
            context_inputs: Vec::new(),
            call_sites: Vec::new(),
            auth_checks: Vec::new(),
            operations: Vec::new(),
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

    fn member(base: &str, field: &str) -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::MemberField,
            name: format!("{base}.{field}"),
            base: Some(base.to_string()),
            field: Some(field.to_string()),
            index: None,
            span: (0, 0),
        }
    }

    #[test]
    fn self_actor_var_widens_actor_context_for_self_id_fields() {
        let mut unit = empty_unit();
        unit.self_actor_vars.insert("user".into());

        // `user.id`-shape subjects count as actor context now.
        assert!(is_actor_context_subject(&member("user", "id"), &unit));
        assert!(is_actor_context_subject(&member("user", "user_id"), &unit));
        assert!(is_actor_context_subject(&member("user", "uid"), &unit));

        // Pitfall guard: `user.group_id` / `user.workspace_id` stay
        // relevant, only self-identifier fields trip the widening.
        assert!(!is_actor_context_subject(
            &member("user", "group_id"),
            &unit
        ));
        assert!(!is_actor_context_subject(
            &member("user", "workspace_id"),
            &unit
        ));

        // Variables not in self_actor_vars fall back to the existing
        // identity-key match, `target.id` still flags.
        assert!(!is_actor_context_subject(&member("target", "id"), &unit));
    }

    #[test]
    fn self_actor_var_suppresses_relevant_subject_for_self_id() {
        let mut unit = empty_unit();
        unit.self_actor_vars.insert("user".into());

        assert!(!is_relevant_target_subject(&member("user", "id"), &unit));
        // Foreign id on the same actor binding still matters.
        assert!(is_relevant_target_subject(
            &member("user", "group_id"),
            &unit
        ));
    }

    fn plain(name: &str) -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::Identifier,
            name: name.to_string(),
            base: None,
            field: None,
            index: None,
            span: (0, 0),
        }
    }

    /// Real-repo regression: `let uid = user.id; query(.., &[uid])`.
    /// `uid` lives in `self_actor_id_vars` and the subject `uid`
    /// (plain Local, no base/field) must count as actor context.
    #[test]
    fn self_actor_id_vars_widens_actor_context_for_plain_subjects() {
        let mut unit = empty_unit();
        unit.self_actor_id_vars.insert("uid".into());

        // `uid` plain subject is recognised as actor context.
        assert!(is_actor_context_subject(&plain("uid"), &unit));
        // Plain identifiers NOT in the set still flag.
        assert!(!is_actor_context_subject(&plain("trip_id"), &unit));
        assert!(!is_actor_context_subject(&plain("doc_id"), &unit));
    }

    /// Self-publish identity fields: `&user.email` /
    /// `&user.username` / `&user.handle` for a self-actor must be
    /// recognised as actor context (real-repo `realtime::publish_to_user`
    /// shape).
    #[test]
    fn self_actor_id_field_set_includes_email_username_handle() {
        let mut unit = empty_unit();
        unit.self_actor_vars.insert("user".into());

        assert!(is_actor_context_subject(&member("user", "email"), &unit));
        assert!(is_actor_context_subject(&member("user", "username"), &unit));
        assert!(is_actor_context_subject(&member("user", "handle"), &unit));

        // Foreign-user fields still flag.
        assert!(!is_actor_context_subject(&member("target", "email"), &unit));
    }

    /// Real-repo regression (gin/context_test.go): `id := "id";
    /// c.AddParam(id, value)` previously fired the rule because `id`
    /// matched is_id_like but had no actor-context exemption.  After
    /// the const-binding tracker, `id` (a plain Local with no base /
    /// field) bound to a literal is excluded from relevant subjects.
    #[test]
    fn const_bound_plain_subjects_are_not_relevant() {
        let mut unit = empty_unit();
        unit.const_bound_vars.insert("id".into());

        // `id` matches is_id_like (name=="id") but is constant-bound.
        assert!(!is_relevant_target_subject(&plain("id"), &unit));

        // Plain `id` NOT in the const-bound set still flags as
        // relevant, regression guard for the user-controlled case.
        let unit2 = empty_unit();
        assert!(is_relevant_target_subject(&plain("id"), &unit2));

        // Member access `req.id` is unaffected by const-bound check
        // (different ValueRef shape).
        unit.const_bound_vars.insert("req".into());
        assert!(is_relevant_target_subject(&member("req", "id"), &unit));
    }

    /// Real-repo regression: caller-passed scope entity used as
    /// ownership constraint (sentry api/helpers/environments.py
    /// `get_environments(request, organization)` and
    /// api/endpoints/organization_releases.py
    /// `_filter_releases_by_query(queryset, organization, query, ...)`).
    /// The helper inherits the caller's auth on the entity object;
    /// the `<entity>.id` arg IS the ownership scope, not a target.
    #[test]
    fn caller_scope_entity_subject_recognises_unit_param_id() {
        let mut unit = empty_unit();
        unit.params.push("organization".into());

        // `organization.id` where `organization` is a unit param and
        // matches the scope-entity vocabulary -> recognised as scope.
        assert!(is_caller_scope_entity_subject(
            &member("organization", "id"),
            &unit
        ));
        assert!(is_caller_scope_entity_subject(
            &member("organization", "pk"),
            &unit
        ));
        // Suppression flows through to `is_relevant_target_subject`.
        assert!(!is_relevant_target_subject(
            &member("organization", "id"),
            &unit
        ));

        // Other scope-entity names: project, team, workspace, ...
        let mut unit_p = empty_unit();
        unit_p.params.push("project".into());
        assert!(is_caller_scope_entity_subject(
            &member("project", "id"),
            &unit_p
        ));

        let mut unit_t = empty_unit();
        unit_t.params.push("team".into());
        assert!(is_caller_scope_entity_subject(&member("team", "id"), &unit_t));

        let mut unit_w = empty_unit();
        unit_w.params.push("workspace".into());
        assert!(is_caller_scope_entity_subject(
            &member("workspace", "id"),
            &unit_w
        ));

        let mut unit_r = empty_unit();
        unit_r.params.push("repo".into());
        assert!(is_caller_scope_entity_subject(&member("repo", "id"), &unit_r));
    }

    /// Pitfall guards for `is_caller_scope_entity_subject`.
    #[test]
    fn caller_scope_entity_subject_does_not_overreach() {
        // `organization` not declared as a unit param -> not exempt.
        let unit = empty_unit();
        assert!(!is_caller_scope_entity_subject(
            &member("organization", "id"),
            &unit
        ));

        // Field other than id/pk -> not exempt (could be display name).
        let mut unit = empty_unit();
        unit.params.push("organization".into());
        assert!(!is_caller_scope_entity_subject(
            &member("organization", "name"),
            &unit
        ));
        assert!(!is_caller_scope_entity_subject(
            &member("organization", "slug"),
            &unit
        ));

        // `user.id` / `member.id` / `actor.id` are deliberately NOT
        // recognised as scope entities (actor semantics, handled by
        // is_actor_context_subject).  They must not be widened here.
        let mut unit_u = empty_unit();
        unit_u.params.push("user".into());
        assert!(!is_caller_scope_entity_subject(&member("user", "id"), &unit_u));

        let mut unit_m = empty_unit();
        unit_m.params.push("member".into());
        assert!(!is_caller_scope_entity_subject(
            &member("member", "id"),
            &unit_m
        ));

        // Bare identifier -> not exempt (no field).
        let mut unit_b = empty_unit();
        unit_b.params.push("organization".into());
        assert!(!is_caller_scope_entity_subject(
            &plain("organization"),
            &unit_b
        ));
    }

    /// Vocabulary check for `is_caller_scope_entity_name`.  Pinned so
    /// future widening is intentional.
    #[test]
    fn caller_scope_entity_name_vocabulary() {
        // Recognised scope entities.
        for name in [
            "organization",
            "Organization",
            "ORG",
            "project",
            "team",
            "workspace",
            "tenant",
            "account",
            "community",
            "group",
            "repository",
            "repo",
            "company",
        ] {
            assert!(
                is_caller_scope_entity_name(name),
                "expected {name} to be recognised as scope entity"
            );
        }
        // Excluded (actor semantics or generic).
        for name in ["user", "member", "actor", "request", "self", "ctx"] {
            assert!(
                !is_caller_scope_entity_name(name),
                "expected {name} NOT to be recognised as scope entity"
            );
        }
    }

    /// Hierarchy: a parameter whose
    /// static type was recovered as `Int`/`Bool` (Spring `Long userId`,
    /// Axum `Path<i64>`, FastAPI `user_id: int`) has its name added to
    /// `unit.typed_bounded_vars` by `apply_typed_bounded_params`.  The
    /// subject `userId` then must not be classified as a scoped
    /// identifier, the framework guarantees the value is numeric and
    /// cannot drive ownership-bypass.
    #[test]
    fn typed_bounded_plain_subjects_are_not_relevant() {
        let mut unit = empty_unit();
        unit.typed_bounded_vars.insert("user_id".into());

        // `user_id` matches is_id_like but is bounded by static type.
        assert!(!is_relevant_target_subject(&plain("user_id"), &unit));

        // Plain `user_id` NOT in the typed-bounded set still flags.
        let unit2 = empty_unit();
        assert!(is_relevant_target_subject(&plain("user_id"), &unit2));

        // Member access `req.user_id` is unaffected (only plain
        // identifiers are exempted, fields/base remain regular
        // subjects so DTO-shape leaks still flag).
        unit.typed_bounded_vars.insert("req".into());
        assert!(is_relevant_target_subject(&member("req", "user_id"), &unit));
    }

    /// Real-repo regression: pure-backend units (Django migrations,
    /// Celery tasks with no params, pytest fixtures) must fail the
    /// user-input precondition so token-override / ownership rules
    /// don't fire.  Conversely, helpers with id-like / token-like /
    /// request-named parameters do count as user-input-bearing.
    #[test]
    fn unit_user_input_evidence_recognises_external_inputs() {
        // Function with no params and no context_inputs (Celery task
        // shape), must NOT count as user-input-bearing.
        let mut unit = empty_unit();
        assert!(!unit_has_user_input_evidence(&unit));

        // Adding internal-typed params (apps, schema_editor, Django
        // migration RunPython callback shape) keeps the gate closed.
        unit.params.push("apps".into());
        unit.params.push("schema_editor".into());
        assert!(!unit_has_user_input_evidence(&unit));

        // pytest hook shape: (config, items), gate stays closed.
        let mut unit = empty_unit();
        unit.params.push("config".into());
        unit.params.push("items".into());
        assert!(!unit_has_user_input_evidence(&unit));

        // Adding an id-like param flips the gate open.
        unit.params.push("doc_id".into());
        assert!(unit_has_user_input_evidence(&unit));

        // Token-named param flips the gate open (Express helper
        // `acceptInvitation(token, currentUser, roleOverride)`).
        let mut unit = empty_unit();
        unit.params.push("token".into());
        unit.params.push("currentUser".into());
        unit.params.push("roleOverride".into());
        assert!(unit_has_user_input_evidence(&unit));

        // Framework request-name param flips the gate open
        // (Django/Flask `def view(request, project_id):`).
        let mut unit = empty_unit();
        unit.params.push("request".into());
        assert!(unit_has_user_input_evidence(&unit));

        // Axum/Actix typed-extractor convention name flips it open.
        let mut unit = empty_unit();
        unit.params.push("path".into());
        assert!(unit_has_user_input_evidence(&unit));

        // RouteHandler kind always wins, regardless of params.
        let mut unit = empty_unit();
        unit.kind = AnalysisUnitKind::RouteHandler;
        assert!(unit_has_user_input_evidence(&unit));
    }

    /// `is_external_input_param_name` covers id-, token-, and
    /// framework-request shapes; bare internal-typed names are
    /// rejected so internal helpers stay outside the gate.
    #[test]
    fn external_input_param_name_classification() {
        // ID-shaped names.
        assert!(is_external_input_param_name("id"));
        assert!(is_external_input_param_name("doc_id"));
        assert!(is_external_input_param_name("groupId"));
        assert!(is_external_input_param_name("voucher_code_ids"));

        // Token-shaped names.
        assert!(is_external_input_param_name("token"));
        assert!(is_external_input_param_name("access_token"));
        assert!(is_external_input_param_name("refreshToken"));

        // Framework request / extractor names.
        assert!(is_external_input_param_name("request"));
        assert!(is_external_input_param_name("req"));
        assert!(is_external_input_param_name("ctx"));
        assert!(is_external_input_param_name("path"));
        assert!(is_external_input_param_name("payload"));
        assert!(is_external_input_param_name("dto"));
        assert!(is_external_input_param_name("query"));

        // Internal-typed names that internal helpers / migrations
        // commonly use must NOT match.
        assert!(!is_external_input_param_name("apps"));
        assert!(!is_external_input_param_name("schema_editor"));
        assert!(!is_external_input_param_name("config"));
        assert!(!is_external_input_param_name("items"));
        assert!(!is_external_input_param_name("promotion"));
        assert!(!is_external_input_param_name("update_rule_variants"));
        assert!(!is_external_input_param_name("manager"));
        // `c` alone is too common as a local variable to count.
        assert!(!is_external_input_param_name("c"));
        // Pytest / unittest.mock fixture-injected mocks: `mock_<x>` /
        // `mocked_<x>` names are MagicMock instances, not user input,
        // even when the suffix (`mock_project_id`) is id-shaped.
        assert!(!is_external_input_param_name("mock_project_id"));
        assert!(!is_external_input_param_name("mock_session"));
        assert!(!is_external_input_param_name("mock_user_id"));
        assert!(!is_external_input_param_name("mocked_request"));
        assert!(!is_external_input_param_name("mocked_token"));
    }

    /// Row-fetch exemption.
    ///
    /// Row var declared at line 10; auth check naming the row appears
    /// at line 20.  An operation at line 10 (the fetch) is exempted
    /// because the auth check authorises the resulting row.  Coverage
    /// is intentionally narrow, operations between fetch (10) and
    /// check (20) that are NOT row-fetch sites must still flag.
    #[test]
    fn row_fetch_exemption_covers_fetch_when_check_names_row() {
        use super::has_row_fetch_exemption;
        use crate::auth_analysis::model::{
            AuthCheck, AuthCheckKind, OperationKind, SensitiveOperation,
        };

        let mut unit = empty_unit();
        // `let community = Community::read(pool, data.community_id)?;` at line 10
        unit.row_population_data.insert(
            "community".to_string(),
            (10, vec![member("data", "community_id")]),
        );
        // Auth check at line 20 with `community` as a subject base.
        unit.auth_checks.push(AuthCheck {
            kind: AuthCheckKind::Membership,
            callee: "check_community_user_action".into(),
            subjects: vec![member("community", "id")],
            span: (0, 0),
            line: 20,
            args: Vec::new(),
            condition_text: None,
            is_route_level: false,
        });

        let fetch_op = SensitiveOperation {
            kind: OperationKind::Read,
            sink_class: None,
            callee: "Community.read".into(),
            subjects: vec![member("data", "community_id")],
            span: (0, 0),
            line: 10,
            text: String::new(),
        };
        assert!(has_row_fetch_exemption(&unit, &fetch_op));

        // Operation at a different line (between fetch and check) is
        // NOT a row-fetch site, exemption does not apply.
        let mid_op = SensitiveOperation {
            kind: OperationKind::Mutation,
            sink_class: None,
            callee: "delete_post".into(),
            subjects: vec![member("data", "post_id")],
            span: (0, 0),
            line: 15,
            text: String::new(),
        };
        assert!(!has_row_fetch_exemption(&unit, &mid_op));
    }

    #[test]
    fn row_fetch_exemption_skips_when_no_check_names_row() {
        use super::has_row_fetch_exemption;
        use crate::auth_analysis::model::{OperationKind, SensitiveOperation};

        let mut unit = empty_unit();
        unit.row_population_data.insert(
            "community".to_string(),
            (10, vec![member("data", "community_id")]),
        );
        // No auth check pushed, exemption must NOT apply.

        let fetch_op = SensitiveOperation {
            kind: OperationKind::Read,
            sink_class: None,
            callee: "Community.read".into(),
            subjects: vec![member("data", "community_id")],
            span: (0, 0),
            line: 10,
            text: String::new(),
        };
        assert!(!has_row_fetch_exemption(&unit, &fetch_op));
    }

    #[test]
    fn row_fetch_exemption_ignores_login_token_checks() {
        use super::has_row_fetch_exemption;
        use crate::auth_analysis::model::{
            AuthCheck, AuthCheckKind, OperationKind, SensitiveOperation,
        };

        let mut unit = empty_unit();
        unit.row_population_data.insert(
            "community".to_string(),
            (10, vec![member("data", "community_id")]),
        );
        // Login-only check on the row should NOT exempt the row-fetch
        //, login proves identity, not authorization.
        unit.auth_checks.push(AuthCheck {
            kind: AuthCheckKind::LoginGuard,
            callee: "require_login".into(),
            subjects: vec![member("community", "id")],
            span: (0, 0),
            line: 20,
            args: Vec::new(),
            condition_text: None,
            is_route_level: false,
        });

        let fetch_op = SensitiveOperation {
            kind: OperationKind::Read,
            sink_class: None,
            callee: "Community.read".into(),
            subjects: vec![member("data", "community_id")],
            span: (0, 0),
            line: 10,
            text: String::new(),
        };
        assert!(!has_row_fetch_exemption(&unit, &fetch_op));
    }

    /// Row-population reverse-walk (lemmy fetch-then-check pattern).
    ///
    /// `let community = Community::read(pool, data.community_id)` at
    /// line 10 records `community → [data.community_id]`.  An auth
    /// check on `community` at line 20 must materially cover any
    /// downstream operation that re-uses `data.community_id` (e.g. a
    /// later `delete_mods_for_community(pool, community_id)`),
    /// because the check authorised access to the row that was
    /// fetched using that id.
    #[test]
    fn auth_check_covers_subject_via_row_population_reverse_walk() {
        use crate::auth_analysis::model::{AuthCheck, AuthCheckKind};

        let mut unit = empty_unit();
        unit.row_population_data.insert(
            "community".to_string(),
            (10, vec![member("data", "community_id")]),
        );
        let check = AuthCheck {
            kind: AuthCheckKind::Membership,
            callee: "check_community_user_action".into(),
            subjects: vec![member("community", "id")],
            span: (0, 0),
            line: 20,
            args: Vec::new(),
            condition_text: None,
            is_route_level: false,
        };

        // Direct member subject `data.community_id` (the original
        // request field), covered via reverse-walk.
        assert!(auth_check_covers_subject(
            &check,
            &member("data", "community_id"),
            &unit
        ));

        // A later op that re-passed the *same* id-bearing argument
        // (`Community::read(pool, data.community_id)`) gets covered
        // even though the check's subject names the row, not the id.
        // Before the fix, this fired as
        // `rs.auth.missing_ownership_check` on lemmy
        // `community/transfer.rs:88` and similar.

        // Negative: an unrelated id (different request field that
        // never populated this row) must NOT be covered.
        assert!(!auth_check_covers_subject(
            &check,
            &member("data", "post_id"),
            &unit
        ));
    }

    /// Subject as plain identifier copied from the request
    /// (`let community_id = data.community_id; let community =
    /// Community::read(pool, community_id);`) must also benefit from
    /// the reverse-walk, `row_population_data["community"]` then
    /// records `[community_id]` (a plain identifier, not the
    /// member-access shape).
    #[test]
    fn auth_check_covers_subject_via_row_population_reverse_walk_plain_arg() {
        use crate::auth_analysis::model::{AuthCheck, AuthCheckKind};

        let mut unit = empty_unit();
        unit.row_population_data
            .insert("community".to_string(), (10, vec![plain("community_id")]));
        let check = AuthCheck {
            kind: AuthCheckKind::Membership,
            callee: "check_community_mod_action".into(),
            subjects: vec![member("community", "id")],
            span: (0, 0),
            line: 20,
            args: Vec::new(),
            condition_text: None,
            is_route_level: false,
        };

        assert!(auth_check_covers_subject(
            &check,
            &plain("community_id"),
            &unit
        ));
        // Different plain id is not covered.
        assert!(!auth_check_covers_subject(&check, &plain("post_id"), &unit));
    }

    /// Local-alias chain coverage (lemmy `community/transfer.rs` shape).
    ///
    /// `let community = Community::read(pool, req.community_id)` at
    /// line 10 records `community → [req.community_id]`.  After the
    /// auth check on the row, the handler aliases the request field
    /// into a local: `let community_id = req.community_id;` then
    /// reuses the bare `community_id` in a downstream sink.
    /// `var_alias_chain["community_id"] = "req.community_id"` lets
    /// the reverse-walk match the population args (which still
    /// contain the original member chain) against the plain subject.
    #[test]
    fn auth_check_covers_subject_via_row_population_alias_chain() {
        use crate::auth_analysis::model::{AuthCheck, AuthCheckKind};

        let mut unit = empty_unit();
        unit.row_population_data.insert(
            "community".to_string(),
            (10, vec![member("req", "community_id")]),
        );
        unit.var_alias_chain
            .insert("community_id".to_string(), "req.community_id".to_string());
        let check = AuthCheck {
            kind: AuthCheckKind::Membership,
            callee: "check_community_user_action".into(),
            subjects: vec![member("community", "id")],
            span: (0, 0),
            line: 20,
            args: Vec::new(),
            condition_text: None,
            is_route_level: false,
        };

        // Sink subject is the bare alias, covered via the chain.
        assert!(auth_check_covers_subject(
            &check,
            &plain("community_id"),
            &unit
        ));

        // The original member-access subject is still covered (no
        // regression in the existing reverse-walk path).
        assert!(auth_check_covers_subject(
            &check,
            &member("req", "community_id"),
            &unit
        ));

        // Plain identifier with no alias entry must NOT be covered.
        assert!(!auth_check_covers_subject(&check, &plain("post_id"), &unit));
    }

    /// Route-level guard short-circuit (FastAPI / Flask /
    /// Django / Spring / Rails / axum decorator-level auth).
    ///
    /// The decorator-level `@requires_role` /
    /// `dependencies=[Depends(requires_access_dag(...))]` /
    /// `before_action :authorize` runs before the handler body and
    /// authorizes every value the handler receives.  The check has
    /// no per-arg `ValueRef` pointing back into the body, so the
    /// per-name subject coverage walk cannot model the semantics.
    /// `auth_check_covers_subject` short-circuits `true` for any
    /// authorization-bearing route-level check (LoginGuard etc. are
    /// already filtered out by `has_prior_subject_auth`).
    #[test]
    fn auth_check_covers_subject_route_level_short_circuits() {
        use crate::auth_analysis::model::{AuthCheck, AuthCheckKind};

        let unit = empty_unit();
        let route_check = AuthCheck {
            kind: AuthCheckKind::Other,
            callee: "requires_access_dag".into(),
            subjects: Vec::new(), // route-level checks carry no body subjects
            span: (0, 0),
            line: 0,
            args: Vec::new(),
            condition_text: None,
            is_route_level: true,
        };

        // Any subject is covered when the check is route-level ,
        // path param, request body field, row-fetch receiver, all of
        // them.  The per-name walk would have rejected each.
        assert!(auth_check_covers_subject(
            &route_check,
            &plain("dag_id"),
            &unit
        ));
        assert!(auth_check_covers_subject(
            &route_check,
            &member("req", "dag_run_id"),
            &unit
        ));
        assert!(auth_check_covers_subject(
            &route_check,
            &plain("dag"),
            &unit
        ));

        // Sanity check: an in-body check with no subjects (the prior
        // shape) does NOT cover arbitrary subjects.  Without the
        // route-level flag, the empty subjects vec means the
        // `check.subjects.iter().any(...)` walk fails for every
        // candidate.
        let in_body_check = AuthCheck {
            kind: AuthCheckKind::Other,
            callee: "requires_access_dag".into(),
            subjects: Vec::new(),
            span: (0, 0),
            line: 0,
            args: Vec::new(),
            condition_text: None,
            is_route_level: false,
        };
        assert!(!auth_check_covers_subject(
            &in_body_check,
            &plain("dag_id"),
            &unit
        ));
    }
}
