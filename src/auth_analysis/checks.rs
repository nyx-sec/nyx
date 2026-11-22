use super::config::AuthAnalysisRules;
use super::model::{
    AnalysisUnit, AnalysisUnitKind, AuthCheck, AuthCheckKind, AuthorizationModel, OperationKind,
    SensitiveOperation, SinkClass, UnitRuntime, ValueRef, ValueSourceKind,
};
use super::naming::{
    is_actor_object, is_caller_identity_name, is_caller_scope_entity_name,
    is_request_payload_segment, is_request_scope_path, is_request_scope_segment,
    is_session_identity_ref,
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
    let web_signal = model.lang_web_framework_signal;
    let lang = model.lang.as_str();
    findings.extend(check_admin_routes(model, rules));
    findings.extend(check_ownership_gaps(model, rules, web_signal, lang));
    findings.extend(check_partial_batch_authorization(
        model, rules, web_signal, lang,
    ));
    findings.extend(check_stale_authorization(model, rules, web_signal, lang));
    findings.extend(check_token_override_without_validation(
        model, rules, web_signal, lang,
    ));
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

fn check_ownership_gaps(
    model: &AuthorizationModel,
    rules: &AuthAnalysisRules,
    web_signal: Option<bool>,
    lang: &str,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        if !unit_has_user_input_evidence(unit, web_signal, lang) {
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
            // An HTTP-client request made from a JS/TS helper that is not a
            // route handler and does not sit in a server file is the browser
            // calling its own backend.  The server end is where the check
            // belongs.
            if op.sink_class == Some(SinkClass::OutboundNetwork)
                && matches!(lang, "javascript" | "typescript")
                && unit.kind != AnalysisUnitKind::RouteHandler
                && unit.runtime != UnitRuntime::Server
            {
                continue;
            }
            // NextAuth callbacks are themselves the authentication
            // boundary, both reads and mutations inside them operate on
            // identity context, so suppress regardless of op kind.
            // Other auth helpers stay read-only-suppressed.
            if is_nextauth_callback_unit(unit) {
                continue;
            }
            if op.kind == OperationKind::Read && unit_is_auth_helper(unit) {
                continue;
            }
            let relevant_subjects: Vec<&ValueRef> = op
                .subjects
                .iter()
                .filter(|s| is_relevant_target_subject(s, unit, lang))
                .filter(|s| !is_row_derived_subject(s, unit, op))
                .collect();
            if relevant_subjects.is_empty() {
                continue;
            }
            if op.kind == OperationKind::Read || op.kind == OperationKind::Mutation {
                if is_delegated_read_with_actor_context(unit, op, &relevant_subjects) {
                    continue;
                }
                // Owner-equality scoping: when the same call composes a
                // foreign-id subject with an actor-context subject (e.g.
                // `db.findFirst({where: {id: input.id, userId: ctx.user.id}})`
                // in a TRPC handler), the actor pin tenant-scopes the
                // query to the authenticated user.  The relevant_subjects
                // filter has already excluded actor-context entries; if
                // the unfiltered op.subjects still carries an
                // actor-context subject, the missing co-binding is the
                // owner-eq witness.
                //
                // `is_actor_context_subject` is constrained: it only
                // accepts subjects whose base is in
                // `is_self_scoped_session_base` (`req.user`,
                // `ctx.session.user`, etc.) OR in the per-unit
                // `self_scoped_session_bases` set populated by the
                // typed-extractor pre-pass (TRPC alias matches,
                // NextAuth callback formals).  Generic `user.id` /
                // `me.id` does not qualify, so unrelated co-occurrences
                // do not over-suppress.
                //
                // Written documents of filter-then-update calls
                // (`Note.findOneAndUpdate({_id: id}, {owner: req.user.id})`)
                // are skipped via `payload_subjects_start`: storing the caller
                // as owner is a write, not a scope.  Other call shapes
                // (`db.update({where: {id}, data: {ownerId: ctx.user.id}})`)
                // have no argument positions to tell apart and stay
                // suppressed.  The
                // owner-eq common case removes ~70 cal.com FPs and
                // matches the canonical Express / TRPC scoping idiom.
                //
                // The caller as a whole object (`owner=request.user`,
                // `author: current_user`) pins a lookup, but in a write it is
                // just a field being stored (`create(project_id=pid,
                // created_by=request.user)`), so it counts as the owner pin
                // only for a lookup callee.
                let lookup = is_lookup_callee(&op.callee);
                // A pin inside an earlier lookup of the chain scopes the rows
                // the final call acts on:
                // `Note.objects.filter(owner=request.user, pk=pk).update(..)`.
                let receiver_lookup = op
                    .callee
                    .rsplit_once('.')
                    .is_some_and(|(receiver, _)| receiver.split('.').any(is_lookup_callee));
                //
                // The receiver chain of the callee is not a co-subject:
                // `req.user.constructor.findById(id)` and
                // `req.user.createMembership(..)` start at the caller, but
                // whether that scopes the call is for `is_owner_scoped_callee`
                // to say, by what the method does.
                let has_actor_co_subject = op.subjects.iter().enumerate().any(|(i, s)| {
                    !is_callee_receiver(s, &op.callee)
                        && op.payload_subjects_start.is_none_or(|start| i < start)
                        && ((is_actor_context_subject(s, unit)
                            && (lookup
                                || (receiver_lookup && i < op.receiver_subjects)
                                || !is_whole_actor_object(s)))
                            || is_viewer_argument_of_view_read(op, s, unit, lang))
                });
                if has_actor_co_subject {
                    continue;
                }
                // Association scoping: `current_user.notes.find(params[:id])`,
                // `request.user.documents.filter(id=doc_id)`.  The query
                // starts at the caller, so it can only return their rows.
                if is_owner_scoped_callee(&op.callee, rules)
                    || is_request_scope_rooted_lookup(&op.callee, unit)
                    || is_authorization_scoped_var_lookup(&op.callee, unit)
                {
                    continue;
                }
                // Scope co-subject: the same call also binds the caller's
                // scope entity (`GetLabelInRepoByID(ctx, repo.ID, labelID)`,
                // `filter(organization_id=organization.id, id=env_id)`), so
                // the lookup is confined to a scope the caller already holds.
                // An unscoped `GetLabelByID(ctx, labelID)` has no such
                // subject and still fires.
                let has_scope_co_subject = op
                    .subjects
                    .iter()
                    .any(|s| is_caller_scope_entity_subject(s, unit));
                if has_scope_co_subject {
                    continue;
                }
                // Tenant pin from an authorised row: the same call also binds
                // the tenant of a row an earlier check covers
                // (`Attachment.findAll({ where: { teamId: document.teamId, id:
                // ids } })` after `authorize(user, "read", document)`), so the
                // lookup cannot leave the tenant the caller was cleared for.
                if has_authorised_tenant_pin(unit, op) {
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
    web_signal: Option<bool>,
    lang: &str,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        if !unit_has_user_input_evidence(unit, web_signal, lang) {
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
    web_signal: Option<bool>,
    lang: &str,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        if !unit_has_user_input_evidence(unit, web_signal, lang) {
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
    web_signal: Option<bool>,
    lang: &str,
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
        if !unit_has_user_input_evidence(unit, web_signal, lang) {
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
            operation.kind == OperationKind::Mutation
                && operation.line >= token_lookup.line
                // Ignore `InMemoryLocal` mutations (HashSet/HashMap/Vec
                // local bookkeeping like `verified_ids.update(myteams)`,
                // `requested_teams.update(verified_ids)`).  The verb is
                // `update` so `OperationKind::Mutation` is set, but the
                // sink_class encodes that the receiver is a non-sink
                // local container — never a token-bound write.  Mirrors
                // the gate in `check_ownership_gaps`.
                && operation
                    .sink_class
                    .is_none_or(|class| class.is_auth_relevant())
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

/// The call binds a tenant field of a row that an earlier authorization check
/// already covers (`teamId: document.teamId` after `authorize(user, "read",
/// document)`).  Only a tenant-like field qualifies: the row's own fields say
/// nothing about which other rows the caller may reach.
fn has_authorised_tenant_pin(unit: &AnalysisUnit, op: &SensitiveOperation) -> bool {
    op.subjects.iter().any(|s| {
        !is_callee_receiver(s, &op.callee)
            && s.base.is_some()
            && !matches!(
                s.source_kind,
                ValueSourceKind::RequestParam
                    | ValueSourceKind::RequestBody
                    | ValueSourceKind::RequestQuery
                    | ValueSourceKind::Session
            )
            && s.base
                .as_deref()
                .map(|b| b.split(['.', '[', '(']).next().unwrap_or(b))
                .is_some_and(|root| !unit.request_roots.contains(root))
            && s.field.as_deref().is_some_and(is_actor_tenant_field)
            && unit.auth_checks.iter().any(|check| {
                check.line <= op.line
                    && !matches!(
                        check.kind,
                        AuthCheckKind::LoginGuard
                            | AuthCheckKind::TokenExpiry
                            | AuthCheckKind::TokenRecipient
                    )
                    && auth_check_covers_subject(check, s, unit)
            })
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
    // Row vars declared at this op's line.  One line can bind several rows
    // (`const [a, b] = await Promise.all([A.find(x), B.find(y)])`).
    let row_vars: Vec<&str> = unit
        .row_population_data
        .iter()
        .filter(|(_, bindings)| bindings.iter().any(|(line, _)| *line == op.line))
        .map(|(var, _)| var.as_str())
        .collect();
    if row_vars.is_empty() {
        return false;
    }
    // A check on a row fetched through this row's own foreign key
    // (`let community = Community::read(pool, tag.community_id)`) authorises
    // the fetch of the child as well.
    let row_vars = rows_with_derived(unit, row_vars);

    // Look for any non-login auth check whose subjects mention a row.
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
            .any(|subj| row_vars.contains(&chain_root(subj)))
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
    // A body-level admin gate that propagates failure dominates every later
    // operation, and an admin may act on any resource.  Line ordering is
    // applied by the callers (`check.line <= op.line`).
    if check.dominates_body && check.kind == AuthCheckKind::AdminGuard {
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
    let direct_populates: Vec<&str> = unit
        .row_population_data
        .iter()
        .filter_map(|(row_var, bindings)| {
            let matches_arg = bindings.iter().flat_map(|(_line, args)| args).any(|arg| {
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
    // Authorising a row reached through the foreign key of a populated row
    // (fetch the child by the request id, then its parent by `child.parent_id`,
    // then check the parent) covers the request id too.
    let subject_populates = rows_with_derived(unit, direct_populates);

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
        subject_anchor_authorized && unit.authorized_sql_vars.contains(&check_key)
    })
}

/// Close `seed` over rows fetched with an argument rooted at a row already in
/// the set (`let parent = Parent::read(pool, child.parent_id)` adds `parent`
/// once `child` is in).  Only row-to-row derivations are followed, so a parent
/// fetched with an unrelated request id is never added.  Bounded by the number
/// of rows in the unit, and cycle-safe because rows are only ever added.
fn rows_with_derived<'a>(unit: &'a AnalysisUnit, seed: Vec<&'a str>) -> Vec<&'a str> {
    let mut rows = seed;
    if rows.is_empty() {
        return rows;
    }
    loop {
        let before = rows.len();
        for (row_var, bindings) in &unit.row_population_data {
            if rows.contains(&row_var.as_str()) {
                continue;
            }
            let derived = bindings.iter().flat_map(|(_line, args)| args).any(|arg| {
                arg.base.is_some()
                    && rows.contains(&chain_root(arg))
                    && is_parent_link(row_var, arg)
            });
            if derived {
                rows.push(row_var.as_str());
            }
        }
        if rows.len() == before {
            return rows;
        }
    }
}

/// Whether `arg` (`child.<field>`) reads like the foreign key to the row
/// bound as `row_var`: the field stem (`community_id` -> `community`) must be
/// the row variable's name or its trailing word (`parent_community`).  A field
/// such as `sibling_id` fetched into `sib` names a peer, not an owner, so a
/// check on that peer does not authorise the child.  When the naming does not
/// line up the derivation is not followed and the finding stays.
fn is_parent_link(row_var: &str, arg: &ValueRef) -> bool {
    let field = arg.name.rsplit('.').next().unwrap_or(arg.name.as_str());
    let lower = field.to_ascii_lowercase();
    let stem = lower
        .strip_suffix("_id")
        .or_else(|| lower.strip_suffix("id"))
        .unwrap_or(lower.as_str())
        .trim_end_matches('_');
    if stem.is_empty() {
        return false;
    }
    let row = row_var.to_ascii_lowercase();
    let norm = |v: &str| v.replace('_', "");
    let (row_n, stem_n) = (norm(&row), norm(stem));
    row_n == stem_n || row_n.ends_with(&stem_n)
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

fn is_relevant_target_subject(subject: &ValueRef, unit: &AnalysisUnit, lang: &str) -> bool {
    (is_id_like(subject) || is_route_primary_key(subject, unit))
        && !is_actor_context_subject(subject, unit)
        && !is_const_bound_subject(subject, unit)
        && !is_typed_bounded_subject(subject, unit)
        && !is_caller_scope_entity_subject(subject, unit)
        && !is_package_level_subject(subject, unit)
        && !is_model_selector_subject(subject, unit, lang)
}

/// True iff `subject` is read off a row the unit already holds, so it names
/// something the code found rather than something the caller supplied.
///
/// A subject counts when its root variable is
///   * a row bound earlier in the unit by a modelled fetch (`pv := Get(..)`,
///     `const doc = await Doc.findByPk(id)`), including an insert's result,
///     whose id the database minted,
///   * a local read off such a row (`const id = res[0].id`), a loop variable
///     over one (`for _, t := range tasks`), or a callback parameter of one
///     (`rows.map(row => ..)`), or
///   * outside a route handler, an entity parameter (`document` in
///     `move(document)`): the caller hands the helper an entity it already
///     loaded.
///
/// The fetch itself is what must be authorised.  In request-bearing code the
/// row only counts when that fetch was keyed by an id or pinned to the
/// caller's scope, so it either reports on its own or is covered by a check.
/// A row found by a bare request-supplied name has no such site, and its
/// fields keep reporting.
fn is_row_derived_subject(
    subject: &ValueRef,
    unit: &AnalysisUnit,
    op: &SensitiveOperation,
) -> bool {
    if matches!(
        subject.source_kind,
        ValueSourceKind::RequestParam
            | ValueSourceKind::RequestBody
            | ValueSourceKind::RequestQuery
            | ValueSourceKind::Session
    ) {
        return false;
    }
    let chain = subject.base.as_deref().unwrap_or(subject.name.as_str());
    let root = chain.split(['.', '[', '(']).next().unwrap_or(chain);
    if root.is_empty() || unit.request_roots.contains(root) {
        return false;
    }
    var_is_held_row(unit, root, op, 0)
}

/// The unit is a route handler or reads the request or request context
/// directly.  A helper that only takes an options bag named `params` or `input`
/// is not: whoever calls it owns the question of where the bag came from.
fn unit_handles_request(unit: &AnalysisUnit) -> bool {
    const REQUEST_NAMES: &[&str] = &["req", "request", "ctx", "event", "res", "response"];
    let is_request_name = |name: &str| REQUEST_NAMES.contains(&name.to_ascii_lowercase().as_str());
    unit.kind == AnalysisUnitKind::RouteHandler
        || !unit.request_roots.is_empty()
        || unit.params.iter().any(|p| is_request_name(p))
        || unit.context_inputs.iter().any(|input| {
            let chain = input.base.as_deref().unwrap_or(input.name.as_str());
            is_request_name(chain.split(['.', '[', '(']).next().unwrap_or(chain))
        })
}

fn var_is_held_row(unit: &AnalysisUnit, var: &str, op: &SensitiveOperation, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    if let Some(bindings) = unit.row_population_data.get(var) {
        let mut prior = bindings
            .iter()
            .filter(|(line, _)| *line < op.line)
            .peekable();
        if prior.peek().is_none() {
            return false;
        }
        return prior.all(|(line, args)| fetch_site_is_authorised_elsewhere(unit, *line, args));
    }
    if let Some(sources) = unit.row_derived_from.get(var) {
        return !sources.is_empty()
            && sources
                .iter()
                .all(|source| source != var && var_is_held_row(unit, source, op, depth + 1));
    }
    // A helper is handed an entity it did not load; a registered handler or a
    // function holding the framework request context is not.
    unit.kind != AnalysisUnitKind::RouteHandler
        && unit.request_roots.is_empty()
        && unit.params.iter().any(|p| p == var)
        && is_entity_param_name(var)
}

/// The fetch at `line` is a data fetch, and it either minted the row (an
/// insert), or it is not in request-bearing code, or it was keyed by an id or
/// scoped to the caller.  A pure conversion such as `parseInt(id)` is not a
/// fetch.
fn fetch_site_is_authorised_elsewhere(unit: &AnalysisUnit, line: usize, args: &[ValueRef]) -> bool {
    let callees = unit.row_fetch_callees.get(&line);
    if callees.is_some_and(|callees| callees.iter().any(|c| is_minting_callee(c))) {
        return true;
    }
    let modelled = unit
        .operations
        .iter()
        .any(|o| o.line == line && o.sink_class.is_none_or(|c| c.is_auth_relevant()));
    let fetch_like = callees.is_some_and(|callees| callees.iter().any(|c| is_row_fetch_callee(c)));
    if !modelled && !fetch_like {
        return false;
    }
    if !unit_handles_request(unit) {
        return true;
    }
    // Pinned to the caller or to a scope the caller holds: nothing outside it
    // can come back, so there is no first fetch left to report.
    if args
        .iter()
        .any(|s| is_actor_context_subject(s, unit) || is_caller_scope_entity_subject(s, unit))
    {
        return true;
    }
    // Keyed by an id: the fetch is a modelled operation that reports, or is
    // covered by a check, on its own.
    unit.operations.iter().any(|o| {
        o.line == line
            && o.sink_class.is_none_or(|c| c.is_auth_relevant())
            && o.subjects
                .iter()
                .any(|s| is_id_like(s) || is_route_primary_key(s, unit))
    })
}

/// A call that reads rows: a lookup, or a query, load, list or search.
fn is_row_fetch_callee(callee: &str) -> bool {
    if is_lookup_callee(callee) {
        return true;
    }
    let method = callee.rsplit('.').next().unwrap_or(callee);
    let lower = method
        .trim_end_matches(['!', '?'])
        .trim_end_matches("()")
        .to_ascii_lowercase();
    [
        "query", "select", "read", "load", "list", "search", "lookup", "retrieve",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

/// `insert`, `create`, `createMany`: the call writes a new row, so the id on
/// the result was minted by the database.  `createQueryBuilder` only starts a
/// query.
fn is_minting_callee(callee: &str) -> bool {
    // The write must be the last real step of the chain. Earlier segments are
    // scopes or accessors (`createdBy`, `createSession().findOne`), so a read
    // after a create/insert-named segment means the row was looked up, not
    // inserted. Only builder and promise tails may follow the write.
    const TAILS: &[&str] = &[
        "then",
        "catch",
        "finally",
        "execute",
        "exec",
        "values",
        "into",
        "returning",
        "save",
    ];
    let normalise = |s: &str| {
        s.trim_end_matches(['!', '?'])
            .trim_end_matches("()")
            .to_ascii_lowercase()
    };
    // Drop call arguments so a dot inside `insert(params.data)` does not
    // split the chain.
    let mut depth = 0usize;
    let bare: String = callee
        .chars()
        .filter(|&c| match c {
            '(' => {
                depth += 1;
                false
            }
            ')' => {
                depth = depth.saturating_sub(1);
                false
            }
            _ => depth == 0,
        })
        .collect();
    for segment in bare.rsplit(['.', ':']).filter(|s| !s.is_empty()) {
        let lower = normalise(segment);
        if TAILS.contains(&lower.as_str()) {
            continue;
        }
        return (lower.starts_with("create") && !lower.starts_with("createquery"))
            || lower.starts_with("insert")
            || lower == "bulkcreate";
    }
    false
}

/// A parameter named for a domain entity, as opposed to an id, a request or an
/// options bag.
fn is_entity_param_name(name: &str) -> bool {
    if is_id_like_name(name) || is_external_input_param_name_for_lang(name, "") {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    const BAGS: &[&str] = &[
        "args",
        "arguments",
        "body",
        "criteria",
        "data",
        "dto",
        "event",
        "filter",
        "filters",
        "form",
        "headers",
        "input",
        "opts",
        "options",
        "params",
        "payload",
        "props",
        "query",
        "req",
        "request",
        "settings",
        "this",
        "self",
    ];
    if BAGS.contains(&lower.as_str()) {
        return false;
    }
    const BAG_SUFFIXES: &[&str] = &[
        "form", "opts", "options", "request", "req", "dto", "payload", "input", "params", "args",
        "body", "data", "query", "filter", "filters", "criteria",
    ];
    !BAG_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

/// `pk`, the Django and DRF name for the row id a viewset action receives
/// (`def destroy(self, request, pk=None)`).  Inside a route handler it is as
/// much a request-supplied id as `doc_id`.  Elsewhere `pk` is too common a name
/// in framework internals to count as one.
fn is_route_primary_key(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    unit.kind == AnalysisUnitKind::RouteHandler
        && subject.source_kind == ValueSourceKind::Identifier
        && subject.name == "pk"
}

/// `uid`, `targetUid`, `componentUID` outside a route handler.  In Strapi and
/// similar codebases a `uid` names a content type (`api::article.article`),
/// and the calls it feeds (`strapi.getModel(uid)`, `db.query(uid)`) select a
/// model rather than a row.  A route handler's `uid` is a path or body value
/// and stays a subject, as does any `uid` read off a request chain or copied
/// from one.
fn is_model_selector_subject(subject: &ValueRef, unit: &AnalysisUnit, lang: &str) -> bool {
    if !matches!(lang, "javascript" | "typescript")
        || unit.kind == AnalysisUnitKind::RouteHandler
        || matches!(
            subject.source_kind,
            ValueSourceKind::RequestParam
                | ValueSourceKind::RequestBody
                | ValueSourceKind::RequestQuery
                | ValueSourceKind::Session
        )
    {
        return false;
    }
    let name = subject
        .field
        .as_deref()
        .or(subject.base.as_deref())
        .unwrap_or(&subject.name);
    super::naming::is_uid_name(name) && !unit.var_alias_chain.contains_key(&subject.name)
}

/// True iff `subject` is rooted at a Go package-level name: an imported
/// package (`common.LDAPUID`, `grid.GetByteBuffer()`) or a file const.  The
/// unit builder already removed every name the function shadows, so what is
/// left names a declaration and cannot carry a per-request value.
fn is_package_level_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    if unit.package_names.is_empty() {
        return false;
    }
    let chain = subject.base.as_deref().unwrap_or(subject.name.as_str());
    let root = chain.split(['.', '[', '(']).next().unwrap_or(chain);
    unit.package_names.contains(root)
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
    if is_caller_scope_entity_name(root) && unit.params.iter().any(|p| p == root) {
        return true;
    }
    is_request_context_scope_subject(base, root, unit)
}

/// `<ctx>.Repo.Repository.ID`, `<ctx>.Org.Organization.ID`,
/// `<ctx>.Package.Owner.ID`: Go frameworks such as gitea resolve the repo,
/// organisation or package owner named in the URL, and check the caller's
/// access to it, before the handler runs.  The chain reads that scope entity
/// off the request context.  A local copy of the entity (`repo :=
/// ctx.Repo.Repository`) counts the same way.
///
/// Chains that pass through request payload (`ctx.Req.Form.ID`) do not.
fn is_request_context_scope_subject(base: &str, root: &str, unit: &AnalysisUnit) -> bool {
    if unit.request_roots.is_empty() || base.contains('(') || !unit.request_roots.contains(root) {
        return false;
    }
    let rest: Vec<&str> = base.split('.').skip(1).collect();
    if rest.is_empty() {
        return is_request_scope_segment(root);
    }
    is_request_scope_path(&rest)
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

    // Go request-context actor: `ctx.Doer.ID`, `c.User.ID`.  The framework
    // resolves the signed-in user onto the context before the handler runs.
    if let Some(base) = subject.base.as_deref()
        && is_request_context_actor_base(base, unit)
        && subject.field.as_deref().is_some_and(is_self_actor_id_field)
    {
        return true;
    }

    // `requester.id`, `requestor.pk`: resolvers receive the authenticated
    // caller under these names, and its own id is not a foreign target.
    if let Some(base) = subject.base.as_deref()
        && is_caller_identity_name(base)
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
            && subject
                .field
                .as_deref()
                .is_some_and(|f| is_self_actor_id_field(f) || is_actor_tenant_field(f))
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

    // A field named like an owner pin (`ownerId`, `createdBy`) is the caller's
    // identity only when the caller supplied it.  `req.query.ownerId` or an
    // `ownerId` route parameter is chosen by whoever sends the request, so
    // pinning a query to it scopes nothing, and writing it reassigns the row.
    if is_request_supplied_subject(subject, unit) {
        return false;
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

/// True when the value comes from the request: a request param, body or query
/// chain, a local copied from one, or a route handler's own bound parameter.
fn is_request_supplied_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    if matches!(
        subject.source_kind,
        ValueSourceKind::RequestParam
            | ValueSourceKind::RequestBody
            | ValueSourceKind::RequestQuery
    ) {
        return true;
    }
    if let Some(chain) = unit.var_alias_chain.get(&subject.name) {
        let root = chain.split('.').next().unwrap_or(chain);
        if matches!(
            root,
            "req" | "request" | "params" | "body" | "query" | "input"
        ) {
            return true;
        }
    }
    // A bare identifier that is a parameter of a route handler is bound from
    // the path, query or body by the framework, unless the framework fills it
    // in itself (a `Depends(..)` default, a custom parameter decorator, an
    // `@AuthenticationPrincipal`).
    unit.kind == AnalysisUnitKind::RouteHandler
        && subject.source_kind == ValueSourceKind::Identifier
        && !unit.injected_params.contains(&subject.name)
        && unit.params.iter().any(|param| param == &subject.name)
}

/// `<root>.Doer`, `<root>.User`, `<root>.Session.User`: the authenticated
/// actor read off a Go request context.
fn is_request_context_actor_base(base: &str, unit: &AnalysisUnit) -> bool {
    if unit.request_roots.is_empty() || base.contains('(') {
        return false;
    }
    let mut segments = base.split('.');
    let (Some(root), Some(_)) = (segments.next(), segments.next()) else {
        return false;
    };
    unit.request_roots.contains(root)
        && base
            .rsplit('.')
            .next()
            .is_some_and(is_request_actor_segment)
}

pub(super) fn is_request_actor_segment(segment: &str) -> bool {
    matches!(
        segment.to_ascii_lowercase().as_str(),
        "doer" | "user" | "signeduser" | "currentuser" | "actor" | "authuser"
    )
}

/// The authenticated actor's own tenant: `user.teamId`, `actor.organizationId`.
/// Reading the caller's own team is not reaching for a foreign one, and a
/// write stamped with it (`create({ userId: user.id, teamId: user.teamId })`)
/// is confined to the caller's tenant.  `workspace_id` and `group_id` are left
/// out on purpose: a user can belong to several, so the field is not
/// necessarily the one the request names.
fn is_actor_tenant_field(field: &str) -> bool {
    let key: String = field
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    matches!(
        key.as_str(),
        "teamid" | "organizationid" | "orgid" | "tenantid" | "accountid"
    )
}

fn is_self_actor_id_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "id" | "_id" | "pk" | "uuid" | "user_id" | "userid" | "uid"
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
    // The caller as an object (`owner=current_user`, `owner: req.user`).  A
    // bare `current_user` is an identifier, not a session chain, so this does
    // not depend on the source kind.
    if is_actor_object(&subject.name) {
        return true;
    }
    if subject.source_kind != ValueSourceKind::Session {
        return false;
    }
    // The identity key of a session container: `session.user_id`,
    // `req.session.userId`, `request.session.uid`, `session[:user_id]`.
    if is_session_identity_ref(&subject.name) {
        return true;
    }
    // `req.session.user.id` has base `req.session.user`; `req.session.userId`
    // has base `req.session` and the whole chain is the entry the allowlist
    // names.  Match either.
    if subject
        .base
        .as_deref()
        .is_some_and(is_self_scoped_session_base)
        || is_self_scoped_session_base(&subject.name)
    {
        return true;
    }
    // One of the caller's own identifiers: `current_user.id`, `request.user.pk`.
    subject.base.as_deref().is_some_and(is_actor_object)
        && subject.field.as_deref().is_some_and(is_self_actor_id_field)
}

/// The caller as a whole object (`current_user`, `request.user`) rather than
/// one of its fields.
fn is_whole_actor_object(subject: &ValueRef) -> bool {
    is_actor_object(&subject.name)
}

/// Rust read-model lookup that takes the viewer: `CommentView::read(pool,
/// comment_id, Some(&local_user_view.local_user), ..)`.  A `*View` type is a
/// joined read model, and its `read`/`list` entry points take the signed-in
/// viewer to filter what the row exposes (blocked, hidden and private
/// content).  The viewer is a sub-object of the self-actor extractor binding
/// (`local_user`, `person`, ...), so it is not an id the generic owner-pin
/// rule can match.  Mutations never qualify: a viewer passed to a write is
/// data being stored.
fn is_viewer_argument_of_view_read(
    op: &SensitiveOperation,
    subject: &ValueRef,
    unit: &AnalysisUnit,
    lang: &str,
) -> bool {
    if !matches!(lang, "rust" | "rs") || op.kind != OperationKind::Read {
        return false;
    }
    // Callees are normalized to `.` separators (`CommentView.read`).
    let mut segments = op.callee.rsplit('.');
    let (Some(method), Some(ty)) = (segments.next(), segments.next()) else {
        return false;
    };
    let is_read_entry = method == "read"
        || method == "list"
        || method.starts_with("read_")
        || method.starts_with("list_");
    let is_view_type = ty.len() > 4
        && ty.ends_with("View")
        && ty.chars().next().is_some_and(|c| c.is_ascii_uppercase());
    if !is_read_entry || !is_view_type {
        return false;
    }
    let root = subject
        .base
        .as_deref()
        .map(|b| b.split('.').next().unwrap_or(b))
        .unwrap_or(subject.name.as_str());
    if !unit.self_actor_vars.contains(root) {
        return false;
    }
    match subject.field.as_deref() {
        None => subject.base.is_none(),
        Some(f) => matches!(f, "local_user" | "person" | "user" | "account" | "profile"),
    }
}

/// True when the subject is (a prefix of) the callee's own receiver chain:
/// `req.user` and `req.user.documents` for `req.user.documents.find`.
fn is_callee_receiver(subject: &ValueRef, callee: &str) -> bool {
    callee
        .strip_prefix(subject.name.as_str())
        .is_some_and(|rest| rest.starts_with('.'))
}

/// True when the callee's method looks rows up or removes them by a key or a
/// filter (`find`, `find_by!`, `get`, `getPosts`, `filter`, `where`, `first`,
/// `findOne`, `updateOne`, `delete_widget`) and so takes the owner pin as part
/// of the query.  Creating, linking and updating methods are not lookups: their
/// arguments are the data being written.
fn is_lookup_callee(callee: &str) -> bool {
    let method = callee.rsplit('.').next().unwrap_or(callee);
    let lower = method
        .trim_end_matches(['!', '?'])
        .trim_end_matches("()")
        .to_ascii_lowercase();
    if lower.contains("create") || lower.starts_with("get_or_") {
        return false;
    }
    lower.starts_with("find")
        || lower.starts_with("get")
        || lower.starts_with("filter")
        // Removing by key through a caller-rooted association
        // (`request.user.dashboard.delete_widget(id)`) selects within it.
        || lower.starts_with("delete")
        || lower.starts_with("destroy")
        || lower.starts_with("remove")
        || matches!(
            lower.as_str(),
            "where" | "first" | "last" | "take" | "fetch" | "exists" | "one" | "one_or_none"
                | "all"
        )
        // Filter-taking writes: the first argument selects the rows.
        || matches!(
            lower.as_str(),
            "update_one" | "updateone" | "update_many" | "updatemany" | "delete_one"
                | "deleteone" | "delete_many" | "deletemany"
        )
}

/// True when the callee reads through a scope that only holds what the caller
/// may reach: `current_user.notes.find`, `request.user.documents.filter`,
/// `req.user.getPosts`, Pundit's `policy_scope(Note).find` and CanCanCan's
/// `Note.accessible_by(ability).find`.
///
/// The scope proves which rows a lookup can return.  It proves nothing about
/// an id passed as data, so a creating or linking method
/// (`current_user.memberships.create(project_id: id)`, `req.user.setRoles(ids)`)
/// is not covered, and neither is a lookup that leaves the caller for its
/// model (`current_user.class.find(id)`).
fn is_owner_scoped_callee(callee: &str, rules: &AuthAnalysisRules) -> bool {
    let Some((receiver, _method)) = callee.rsplit_once('.') else {
        return false;
    };
    // The lookup is either the callee itself (`current_user.notes.find`) or an
    // earlier call of the chain that the callee then acts on
    // (`current_user.notes.find(id).destroy`).
    if !is_lookup_callee(callee) && !receiver.split('.').any(is_lookup_callee) {
        // `current_user.update(..)` changes the caller's own record, which is
        // the caller's to change.
        return is_actor_object(receiver)
            && matches!(
                callee
                    .rsplit('.')
                    .next()
                    .map(|m| m.trim_end_matches(['!', '?'])),
                Some("update" | "update_attributes" | "save" | "touch")
            );
    }
    // A chain (`current_user.notes.where(..).find`) is still rooted at the
    // caller as long as its first segments name it.
    let mut prefix_end = 0;
    let mut scoped = false;
    for (idx, segment) in receiver.split('.').enumerate() {
        let name = segment.trim_end_matches("()");
        if scoped
            && matches!(
                name,
                "class" | "klass" | "constructor" | "__class__" | "model" | "_default_manager"
            )
        {
            return false;
        }
        if !scoped
            && (name == "accessible_by"
                || (idx == 0 && name == "policy_scope")
                || rules
                    .authorization_scope_segments
                    .iter()
                    .any(|scope| scope == name))
        {
            scoped = true;
        }
        prefix_end += segment.len();
        if !scoped && is_actor_object(&receiver[..prefix_end]) {
            scoped = true;
        }
        prefix_end += 1;
    }
    scoped
}

/// `scope = Project.visible; scope.find(params[:id])`: the receiver is a local
/// bound to a relation an authorization scope already confined.  The callee
/// must be a lookup, like the chain form.
fn is_authorization_scoped_var_lookup(callee: &str, unit: &AnalysisUnit) -> bool {
    if unit.authorization_scoped_vars.is_empty() {
        return false;
    }
    let Some((receiver, _)) = callee.rsplit_once('.') else {
        return false;
    };
    let root = receiver.split('.').next().unwrap_or(receiver);
    unit.authorization_scoped_vars.contains(root)
        && (is_lookup_callee(callee) || receiver.split('.').any(is_lookup_callee))
        && !receiver.split('.').any(|seg| {
            matches!(
                seg,
                "class" | "klass" | "constructor" | "__class__" | "model" | "_default_manager"
            )
        })
}

/// `GetUserByID`, `FindMemberByName`: a fetch of a user, member or team by key.
/// Reaching it through a scope entity does not confine it, since the method
/// reads the entity type's table, not the scope's own rows.
fn is_keyed_identity_fetch(lower_method: &str) -> bool {
    let rest = ["get", "find", "load", "fetch", "lookup"]
        .iter()
        .find_map(|p| lower_method.strip_prefix(p))
        .unwrap_or(lower_method);
    [
        "user",
        "member",
        "team",
        "org",
        "account",
        "collaborator",
        "owner",
    ]
    .iter()
    .any(|entity| {
        rest.strip_prefix(entity)
            .is_some_and(|tail| tail.trim_start_matches('s').starts_with("by"))
    })
}

/// Go: a read through the scope entity the request context already holds,
/// `ctx.Repo.GitRepo.GetCommit(sha)` or `gitRepo.GetCommit(sha)` after
/// `gitRepo := ctx.Repo.GitRepo`.  The router middleware resolved that entity
/// and checked the caller's access to it, so a lookup on it returns only what
/// lies inside.  Only reading methods qualify: removing or adding through the
/// entity (`ctx.Org.Team.RemoveRepository(id)`) acts on a foreign id and
/// still fires, as does a lookup that goes through request payload.
fn is_request_scope_rooted_lookup(callee: &str, unit: &AnalysisUnit) -> bool {
    if unit.request_roots.is_empty() || callee.contains('(') {
        return false;
    }
    let Some((receiver, method)) = callee.rsplit_once('.') else {
        return false;
    };
    if !is_lookup_callee(method) {
        return false;
    }
    let lower = method.to_ascii_lowercase();
    if lower.starts_with("delete") || lower.starts_with("destroy") || lower.starts_with("remove") {
        return false;
    }
    if is_keyed_identity_fetch(&lower) {
        return false;
    }
    let mut segments = receiver.split('.');
    let root = segments.next().unwrap_or(receiver);
    let rest: Vec<&str> = segments.collect();
    if unit.request_scope_roots.contains(root) {
        return !rest.iter().any(|seg| is_request_payload_segment(seg));
    }
    unit.request_roots.contains(root) && is_request_scope_path(&rest)
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
            | "ctx.state.auth.user"
            | "g.user"
            | "self.request.user"
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
    if (normalized.starts_with("has")
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
    {
        return true;
    }
    is_nextauth_callback_unit(unit)
}

/// True when this unit IS, or LEXICALLY CONTAINS, a NextAuth
/// (next-auth) callback definition.
///
/// Two shapes are recognised:
///   * A unit whose name is `signIn` / `session` / `jwt` / `redirect` /
///     `authorize` / `authorized` AND whose destructured params include
///     a canonical NextAuth formal (`user` / `token` / `account` /
///     `profile` / `credentials` / `session` / `trigger`).  Matches the
///     flat `export const authOptions = { callbacks: { ... } }` shape
///     where the top-level unit-creation pass walks into the object
///     literal and produces one unit per method.
///   * A unit whose body contains an object literal with a
///     `callbacks: { ... }` property naming at least one NextAuth
///     callback (set by `body_returns_nextauth_options` at extract
///     time).  Matches the `export const getOptions = (...) =>
///     ({ callbacks: { ... } })` shape where the inner callback
///     methods do not become their own units — operations from their
///     bodies get accumulated under the outer arrow's unit, so the
///     outer unit's name (`getOptions`) is the only handle the
///     suppressor can latch onto.
///
/// NextAuth callbacks ARE the authentication boundary; operations on
/// `user.id` / `existingUser.id` inside them resolve the authenticated
/// identity, they do not look up a tenant-scoped resource based on
/// untrusted input.
fn is_nextauth_callback_unit(unit: &AnalysisUnit) -> bool {
    if unit.is_nextauth_options_factory {
        return true;
    }
    let Some(name) = unit.name.as_deref() else {
        return false;
    };
    if !matches!(
        name,
        "signIn" | "session" | "jwt" | "redirect" | "authorize" | "authorized"
    ) {
        return false;
    }
    const SIGNAL_PARAMS: &[&str] = &[
        "user",
        "token",
        "account",
        "profile",
        "credentials",
        "session",
        "trigger",
    ];
    unit.params
        .iter()
        .any(|p| SIGNAL_PARAMS.contains(&p.as_str()))
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
/// names (which carry no `ValueRef` structure).  A parameter `doc_id` /
/// `groupId` / `userIds` is recognised as an id-bearing input.
fn is_id_like_name(name: &str) -> bool {
    super::naming::is_id_like_name(name)
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
fn unit_has_user_input_evidence(unit: &AnalysisUnit, web_signal: Option<bool>, lang: &str) -> bool {
    if unit.kind == AnalysisUnitKind::RouteHandler {
        return true;
    }
    // Browser code (React components, hooks, SPA helpers) cannot enforce
    // authorization, so its calls into stores and SDKs are not unchecked
    // data access.
    if unit.runtime == UnitRuntime::Browser {
        return false;
    }
    // Project-level web-framework gate.  When the project's manifest
    // was inspected and named no web framework matching the file's
    // language, AND no per-file import override applied, the file
    // lives in a project with no HTTP boundary.  Step 2 (context
    // inputs) and step 3 (param-name heuristic) are both name-shape
    // heuristics that overshoot in non-web Rust crates ─ e.g. zed's
    // GUI test code where `session.update(cx, ...)` (a debug-session
    // handle, not an auth session) trips `matches_session_context`
    // and lands in `context_inputs`, opening every test method's
    // sinks.  Refuse here, after the RouteHandler step (which is
    // determined by framework extractors and is robust evidence on
    // its own).
    if web_signal == Some(false) {
        return false;
    }
    if !unit.context_inputs.is_empty() {
        return true;
    }
    // A module-private Python helper that only non-route code calls is not
    // an entry point (see `AnalysisUnit::internal_helper`).
    if unit.internal_helper {
        return false;
    }
    unit.params
        .iter()
        .any(|p| is_external_input_param_name_for_lang(p, lang))
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
#[cfg(test)]
fn is_external_input_param_name(name: &str) -> bool {
    is_external_input_param_name_for_lang(name, "")
}

/// Lang-aware variant of [`is_external_input_param_name`].  When `lang`
/// names a language whose framework conventions don't use the generic
/// typed-extractor names from the JS/TS/Python ecosystems, the
/// framework-name allow-list is narrowed accordingly.
///
/// Currently narrowed for Go.  In Go the names `ctx` / `context` /
/// `info` / `body` / `path` / `payload` / `dto` / `form` / `query` are
/// not framework-request indicators — they're, respectively,
/// `context.Context` (cancellation/value-bag from the stdlib) and a
/// menagerie of struct-pointer payload params (`info *PackageInfo`,
/// `opts *FooOptions`).  Go's actual HTTP frameworks bind the request
/// to a per-framework typed param (`r *http.Request`, `c *gin.Context`,
/// `c echo.Context`, `c *fiber.Ctx`, `ctx *context.APIContext`); these
/// arrive at the gate via `kind == RouteHandler` (set by the route
/// extractor) or via the type-aware param filter in
/// `extract::common::collect_param_names` (which keeps `ctx` only when
/// its type is **not** the stdlib `context.Context`).
///
/// Real-repo trigger: `/Users/elipeter/oss/gitea` ─ ~1900
/// `go.auth.missing_ownership_check` findings on backend helpers whose
/// only "user-input evidence" was a `ctx context.Context` param name.
fn is_external_input_param_name_for_lang(name: &str, lang: &str) -> bool {
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
    // In JS/TS a `uid` parameter is as likely a schema selector (Strapi's
    // content-type UID) as a row id, so it does not mark a helper as an
    // entry point on its own.
    let uid_selector =
        matches!(lang, "javascript" | "typescript") && super::naming::is_uid_name(name);
    if is_id_like_name(name) && !uid_selector {
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
    if matches!(lang, "go") {
        // Go's allow-list: only `req` / `request` (the stdlib
        // `*http.Request` convention).  All other names from the
        // generic allow-list have language-specific meanings in Go
        // that aren't user-input ─ see fn doc-comment above.
        return matches!(lower.as_str(), "req" | "request");
    }
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
        && super::naming::is_id_collection_name(&subject.name)
}

#[cfg(test)]
mod tests {
    use super::{
        auth_check_covers_subject, is_actor_context_subject, is_caller_scope_entity_name,
        is_caller_scope_entity_subject, is_external_input_param_name,
        is_external_input_param_name_for_lang, is_relevant_target_subject as relevant_in,
        unit_has_user_input_evidence,
    };
    use crate::auth_analysis::model::{
        AnalysisUnit, AnalysisUnitKind, UnitRuntime, ValueRef, ValueSourceKind,
    };
    use std::collections::{HashMap, HashSet};

    /// `is_relevant_target_subject` as the JS/TS pass calls it.
    fn is_relevant_target_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
        relevant_in(subject, unit, "typescript")
    }

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
        assert!(is_caller_scope_entity_subject(
            &member("team", "id"),
            &unit_t
        ));

        let mut unit_w = empty_unit();
        unit_w.params.push("workspace".into());
        assert!(is_caller_scope_entity_subject(
            &member("workspace", "id"),
            &unit_w
        ));

        let mut unit_r = empty_unit();
        unit_r.params.push("repo".into());
        assert!(is_caller_scope_entity_subject(
            &member("repo", "id"),
            &unit_r
        ));
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
        assert!(!is_caller_scope_entity_subject(
            &member("user", "id"),
            &unit_u
        ));

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
        assert!(!unit_has_user_input_evidence(&unit, None, ""));

        // Adding internal-typed params (apps, schema_editor, Django
        // migration RunPython callback shape) keeps the gate closed.
        unit.params.push("apps".into());
        unit.params.push("schema_editor".into());
        assert!(!unit_has_user_input_evidence(&unit, None, ""));

        // pytest hook shape: (config, items), gate stays closed.
        let mut unit = empty_unit();
        unit.params.push("config".into());
        unit.params.push("items".into());
        assert!(!unit_has_user_input_evidence(&unit, None, ""));

        // Adding an id-like param flips the gate open.
        unit.params.push("doc_id".into());
        assert!(unit_has_user_input_evidence(&unit, None, ""));

        // Token-named param flips the gate open (Express helper
        // `acceptInvitation(token, currentUser, roleOverride)`).
        let mut unit = empty_unit();
        unit.params.push("token".into());
        unit.params.push("currentUser".into());
        unit.params.push("roleOverride".into());
        assert!(unit_has_user_input_evidence(&unit, None, ""));

        // Framework request-name param flips the gate open
        // (Django/Flask `def view(request, project_id):`).
        let mut unit = empty_unit();
        unit.params.push("request".into());
        assert!(unit_has_user_input_evidence(&unit, None, ""));

        // Axum/Actix typed-extractor convention name flips it open.
        let mut unit = empty_unit();
        unit.params.push("path".into());
        assert!(unit_has_user_input_evidence(&unit, None, ""));

        // RouteHandler kind always wins, regardless of params.
        let mut unit = empty_unit();
        unit.kind = AnalysisUnitKind::RouteHandler;
        assert!(unit_has_user_input_evidence(&unit, None, ""));
    }

    /// Web-framework signal `Some(false)` (project's manifest was
    /// inspected and named no web framework matching the file's
    /// language, AND no per-file import override) suppresses both
    /// the `context_inputs` arm and the param-name arm — both are
    /// name-shape heuristics that overshoot in non-web Rust crates
    /// (e.g. a debug-session handle named `session` trips
    /// `matches_session_context` and lands in `context_inputs`).
    /// Only RouteHandler classification (step 1) survives the gate
    /// because that flag is set by framework extractors with concrete
    /// route-registration evidence.
    #[test]
    fn web_framework_signal_gates_user_input_heuristics() {
        // Param-name arm: helper named `<thing>_id` in a project the
        // auth detector confirmed has no Rust web framework.  Without
        // the gate this would flip step 3 open and flood the rule on
        // every desktop helper.
        let mut unit = empty_unit();
        unit.params.push("session_id".into());
        assert!(unit_has_user_input_evidence(&unit, None, ""));
        assert!(unit_has_user_input_evidence(&unit, Some(true), ""));
        assert!(!unit_has_user_input_evidence(&unit, Some(false), ""));

        // Step 1 (RouteHandler) still wins regardless of the gate.
        // RouteHandler kind is set by framework extractors (axum /
        // actix_web / rocket) on concrete route-registration shapes —
        // robust enough to bypass the project-level gate even when
        // the manifest doesn't name the framework.
        unit.kind = AnalysisUnitKind::RouteHandler;
        assert!(unit_has_user_input_evidence(&unit, Some(false), ""));

        // context_inputs arm: bare `session.foo` on a debug-session
        // handle (not an auth session) lands in `context_inputs` via
        // `matches_session_context`.  The gate suppresses this so
        // non-web Rust crates don't fire on `session.update(cx, ...)`
        // shapes from desktop test code.
        let mut unit = empty_unit();
        unit.context_inputs.push(ValueRef {
            source_kind: ValueSourceKind::Session,
            name: "session.update".into(),
            base: Some("session".into()),
            field: Some("update".into()),
            index: None,
            span: (0, 0),
        });
        assert!(unit_has_user_input_evidence(&unit, None, ""));
        assert!(unit_has_user_input_evidence(&unit, Some(true), ""));
        assert!(!unit_has_user_input_evidence(&unit, Some(false), ""));
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

    /// Go-specific narrowing of the framework-request-name allow-list.
    ///
    /// Go has no framework convention that uses the generic
    /// typed-extractor names from JS/TS/Python (`info`, `path`,
    /// `payload`, `body`, `dto`, `form`, `query`).  In Go these are
    /// either struct-pointer payload params (`info *PackageInfo`),
    /// stdlib types (`ctx context.Context`), or local variables.
    /// The Go HTTP frameworks bind the request via per-framework typed
    /// params (`r *http.Request`, `c *gin.Context`, `c echo.Context`,
    /// `ctx *context.APIContext`), arriving at the gate via
    /// RouteHandler kind.  Real-repo trigger:
    /// `/Users/elipeter/oss/gitea` ─ ~1900 helpers passing the gate
    /// solely on `ctx context.Context`.
    #[test]
    fn external_input_param_name_for_go_narrows_allowlist() {
        use super::is_external_input_param_name_for_lang as f;
        // ID-shaped + token-shaped names always fire (cross-language).
        assert!(f("user_id", "go"));
        assert!(f("repoID", "go"));
        assert!(f("access_token", "go"));
        // Stdlib `r *http.Request` convention preserved.
        assert!(f("req", "go"));
        assert!(f("request", "go"));
        // Names that Go does NOT use as a request indicator.
        assert!(!f("ctx", "go"));
        assert!(!f("context", "go"));
        assert!(!f("info", "go"));
        assert!(!f("body", "go"));
        assert!(!f("path", "go"));
        assert!(!f("payload", "go"));
        assert!(!f("dto", "go"));
        assert!(!f("form", "go"));
        assert!(!f("query", "go"));
        // Same names DO fire for non-Go languages (Express / NestJS /
        // FastAPI / Axum extractor conventions).
        assert!(f("ctx", "javascript"));
        assert!(f("body", "typescript"));
        assert!(f("path", "rust"));
        assert!(f("payload", "python"));
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
            vec![(10, vec![member("data", "community_id")])],
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
            dominates_body: false,
        });

        let fetch_op = SensitiveOperation {
            kind: OperationKind::Read,
            sink_class: None,
            callee: "Community.read".into(),
            subjects: vec![member("data", "community_id")],
            receiver_subjects: 0,
            payload_subjects_start: None,
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
            receiver_subjects: 0,
            payload_subjects_start: None,
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
            vec![(10, vec![member("data", "community_id")])],
        );
        // No auth check pushed, exemption must NOT apply.

        let fetch_op = SensitiveOperation {
            kind: OperationKind::Read,
            sink_class: None,
            callee: "Community.read".into(),
            subjects: vec![member("data", "community_id")],
            receiver_subjects: 0,
            payload_subjects_start: None,
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
            vec![(10, vec![member("data", "community_id")])],
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
            dominates_body: false,
        });

        let fetch_op = SensitiveOperation {
            kind: OperationKind::Read,
            sink_class: None,
            callee: "Community.read".into(),
            subjects: vec![member("data", "community_id")],
            receiver_subjects: 0,
            payload_subjects_start: None,
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
            vec![(10, vec![member("data", "community_id")])],
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
            dominates_body: false,
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
        unit.row_population_data.insert(
            "community".to_string(),
            vec![(10, vec![plain("community_id")])],
        );
        let check = AuthCheck {
            kind: AuthCheckKind::Membership,
            callee: "check_community_mod_action".into(),
            subjects: vec![member("community", "id")],
            span: (0, 0),
            line: 20,
            args: Vec::new(),
            condition_text: None,
            is_route_level: false,
            dominates_body: false,
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
            vec![(10, vec![member("req", "community_id")])],
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
            dominates_body: false,
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
            dominates_body: false,
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
            dominates_body: false,
        };
        assert!(!auth_check_covers_subject(
            &in_body_check,
            &plain("dag_id"),
            &unit
        ));
    }

    fn session_member(base: &str, field: &str) -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::Session,
            ..member(base, field)
        }
    }

    #[test]
    fn session_user_id_chains_are_self_scoped() {
        let unit = empty_unit();
        for (base, field) in [
            ("req.session", "userId"),
            ("request.session", "uid"),
            ("session", "userId"),
            ("ctx.session", "userId"),
            ("ctx.state.user", "id"),
            ("ctx.state.auth.user", "id"),
        ] {
            assert!(
                is_actor_context_subject(&session_member(base, field), &unit),
                "{base}.{field}"
            );
        }
        // A foreign id carried on the session is not the caller.
        assert!(!is_actor_context_subject(
            &session_member("req.session", "workspaceId"),
            &unit
        ));
    }

    #[test]
    fn actor_tenant_fields_are_the_callers_own_tenant() {
        let mut unit = empty_unit();
        unit.self_actor_vars.insert("user".into());
        assert!(is_actor_context_subject(&member("user", "teamId"), &unit));
        assert!(is_actor_context_subject(
            &member("user", "organization_id"),
            &unit
        ));
        // A variable that is not the actor keeps its tenant ids relevant.
        assert!(!is_actor_context_subject(
            &member("target", "teamId"),
            &unit
        ));
    }

    #[test]
    fn request_context_chains_resolve_scope_and_actor() {
        let mut unit = empty_unit();
        unit.request_roots.insert("ctx".into());
        let repo_id = member("ctx.Repo.Repository", "ID");
        assert!(is_caller_scope_entity_subject(&repo_id, &unit));
        assert!(!is_relevant_target_subject(&repo_id, &unit));
        assert!(is_caller_scope_entity_subject(
            &member("ctx.Package.Owner", "ID"),
            &unit
        ));
        // Payload chains and unrelated entities are not scope.
        assert!(!is_caller_scope_entity_subject(
            &member("ctx.Req.Form", "ID"),
            &unit
        ));
        assert!(!is_caller_scope_entity_subject(
            &member("ctx.Issue", "ID"),
            &unit
        ));
        // Only request roots count.
        assert!(!is_caller_scope_entity_subject(
            &member("other.Repo.Repository", "ID"),
            &unit
        ));
        // `ctx.Doer.ID` is the signed-in user.
        assert!(is_actor_context_subject(&member("ctx.Doer", "ID"), &unit));
        assert!(!is_actor_context_subject(&member("ctx.Issue", "ID"), &unit));
        // A local copy of a scope entity read off the context.
        unit.request_roots.insert("repo".into());
        assert!(is_caller_scope_entity_subject(&member("repo", "ID"), &unit));
    }

    #[test]
    fn package_level_names_are_not_subjects_unless_shadowed() {
        let mut unit = empty_unit();
        unit.package_names.insert("common".into());
        unit.package_names.insert("storageRESTDiskID".into());
        assert!(!is_relevant_target_subject(
            &member("common", "LDAPUID"),
            &unit
        ));
        assert!(!is_relevant_target_subject(
            &plain("storageRESTDiskID"),
            &unit
        ));
        // The unit builder removes shadowed names from the set, so an id on
        // anything else stays a subject.
        assert!(is_relevant_target_subject(&member("event", "ID"), &unit));
    }

    #[test]
    fn uid_is_a_model_selector_outside_route_handlers() {
        let mut unit = empty_unit();
        assert!(!is_relevant_target_subject(&plain("uid"), &unit));
        assert!(!is_relevant_target_subject(&plain("targetUid"), &unit));
        // Only JS/TS read a `uid` as a schema selector.
        assert!(relevant_in(&plain("uid"), &unit, "python"));
        // A real identifier keeps its meaning.
        assert!(is_relevant_target_subject(&plain("userId"), &unit));
        assert!(is_relevant_target_subject(&plain("uuid"), &unit));
        // A `uid` copied from a request chain stays a subject.
        unit.var_alias_chain
            .insert("uid".into(), "req.params.uid".into());
        assert!(is_relevant_target_subject(&plain("uid"), &unit));
        // So does one in a route handler.
        let mut route = empty_unit();
        route.kind = AnalysisUnitKind::RouteHandler;
        assert!(is_relevant_target_subject(&plain("uid"), &route));
    }

    #[test]
    fn browser_units_have_no_user_input_evidence() {
        let mut unit = empty_unit();
        unit.params.push("userId".into());
        assert!(unit_has_user_input_evidence(&unit, None, "typescript"));
        unit.runtime = UnitRuntime::Browser;
        assert!(!unit_has_user_input_evidence(&unit, None, "typescript"));
        // A registered route handler is never browser code.
        unit.kind = AnalysisUnitKind::RouteHandler;
        assert!(unit_has_user_input_evidence(&unit, None, "typescript"));
    }

    #[test]
    fn uid_param_is_not_evidence_but_user_id_is() {
        assert!(!is_external_input_param_name_for_lang("uid", "typescript"));
        assert!(!is_external_input_param_name_for_lang(
            "targetUid",
            "javascript"
        ));
        assert!(is_external_input_param_name_for_lang(
            "userId",
            "typescript"
        ));
        assert!(is_external_input_param_name_for_lang("uuid", "typescript"));
        // Other languages keep `uid` as an id.
        assert!(is_external_input_param_name("uid"));
    }

    #[test]
    fn caller_objects_and_their_own_ids_are_actor_context() {
        let unit = empty_unit();
        // A bare `current_user` is an identifier, not a session chain.
        for name in ["current_user", "current_account", "g.user", "request.user"] {
            assert!(
                is_actor_context_subject(&plain(name), &unit),
                "whole object {name}"
            );
        }
        for (base, field) in [
            ("current_user", "id"),
            ("current_user", "pk"),
            ("g.user", "id"),
            ("request.user", "pk"),
            ("req.user", "_id"),
        ] {
            assert!(
                is_actor_context_subject(&session_member(base, field), &unit),
                "{base}.{field}"
            );
        }
        // Other fields of `current_user` are not the caller's identity.
        assert!(!is_actor_context_subject(
            &session_member("current_user", "organization_id"),
            &unit
        ));
        // Another object with an id is not the caller.
        assert!(!is_actor_context_subject(&member("note", "id"), &unit));
    }

    #[test]
    fn owner_scoped_callees_start_at_the_caller_or_a_policy_scope() {
        let rules = crate::auth_analysis::config::build_auth_rules(
            &crate::utils::config::Config::default(),
            "ruby",
        );
        let scoped = |callee: &str| super::is_owner_scoped_callee(callee, &rules);
        assert!(scoped("current_user.notes.find"));
        assert!(scoped("current_user.notes.where().find"));
        assert!(scoped("request.user.documents.filter"));
        assert!(scoped("req.user.getPosts"));
        assert!(scoped("current_account.projects.find_by!"));
        assert!(scoped("policy_scope.find"));
        assert!(scoped("Note.accessible_by.find"));
        // The scope proves which rows a lookup returns, not that an id passed
        // as data may be linked to the caller.
        assert!(!scoped("current_user.memberships.create"));
        assert!(!scoped("req.user.setRoles"));
        assert!(!scoped("request.user.favorites.create"));
        assert!(!scoped("current_user.notes.find_or_create_by"));
        assert!(scoped("current_user.notes.destroy"));
        assert!(scoped("request.user.dashboard.delete_widget"));
        assert!(scoped("current_user.update!"));
        assert!(scoped("current_user.save"));
        assert!(!scoped("current_user.notes.update"));
        // A lookup earlier in the chain is what selects the row.
        assert!(scoped("current_user.notes.find().destroy"));
        // A lookup that leaves the caller for its model is unscoped.
        assert!(!scoped("current_user.class.find"));
        assert!(!scoped("req.user.constructor.findById"));
        // A view's loaded object is only as scoped as the queryset it came
        // from, which this check cannot see.
        assert!(!scoped("self.object.items.filter"));
        assert!(!scoped("Note.find"));
        assert!(!scoped("notes.find"));
        assert!(!scoped("find"));
        // The user's name in a later segment does not scope the query.
        assert!(!scoped("Note.current_user.find"));
        // An authorization scope confines the lookup that follows it.
        assert!(scoped("Issue.viewable_by.find"));
        assert!(scoped("project.issues.readable_by.find_by"));
        assert!(scoped("User.viewable_by.active.find"));
        assert!(!scoped("Issue.viewable_by"));
        assert!(!scoped("Issue.find"));
        assert!(!scoped("Issue.where.visible_by.find"));
        assert!(!scoped("Issue.viewable_by.klass.find"));
        assert!(!scoped("Issue.viewable_by.model.find"));
        // Bare `visible` is usually a publish flag, so it scopes nothing.
        assert!(!scoped("Issue.visible.find"));
        // Other languages carry no such scope vocabulary.
        let py = crate::auth_analysis::config::build_auth_rules(
            &crate::utils::config::Config::default(),
            "python",
        );
        assert!(!super::is_owner_scoped_callee(
            "Issue.viewable_by.find",
            &py
        ));
    }

    #[test]
    fn request_supplied_owner_pins_are_not_actor_context() {
        let mut unit = empty_unit();
        let owner_from = |kind: ValueSourceKind| ValueRef {
            source_kind: kind,
            ..member("req.query", "ownerId")
        };
        assert!(!is_actor_context_subject(
            &owner_from(ValueSourceKind::RequestQuery),
            &unit
        ));
        assert!(!is_actor_context_subject(
            &owner_from(ValueSourceKind::RequestBody),
            &unit
        ));
        // A local copied from a request chain.
        unit.var_alias_chain
            .insert("ownerId".to_string(), "req.query.ownerId".to_string());
        assert!(!is_actor_context_subject(&plain("ownerId"), &unit));
        // A route handler's own `owner_id` parameter.
        let mut route = empty_unit();
        route.kind = AnalysisUnitKind::RouteHandler;
        route.params.push("owner_id".to_string());
        assert!(!is_actor_context_subject(&plain("owner_id"), &route));
        // A local `ownerId` that came from nowhere visible keeps its meaning.
        assert!(is_actor_context_subject(&plain("ownerId"), &empty_unit()));
        assert!(is_actor_context_subject(
            &member("doc", "createdBy"),
            &empty_unit()
        ));
    }

    #[test]
    fn framework_injected_params_are_not_request_supplied() {
        let mut route = empty_unit();
        route.kind = AnalysisUnitKind::RouteHandler;
        route.params.push("currentUserId".to_string());
        // A bare handler parameter is request-supplied ..
        assert!(!is_actor_context_subject(&plain("currentUserId"), &route));
        // .. unless the framework injects it.
        route.injected_params.insert("currentUserId".to_string());
        assert!(is_actor_context_subject(&plain("currentUserId"), &route));
    }

    #[test]
    fn whole_actor_object_pins_lookups_only() {
        use super::{is_lookup_callee, is_whole_actor_object};
        let unit = empty_unit();
        let subject = plain("request.user");
        assert!(is_whole_actor_object(&subject));
        assert!(is_actor_context_subject(&subject, &unit));
        assert!(is_lookup_callee("Document.objects.filter"));
        assert!(is_lookup_callee("Doc.findOne"));
        assert!(is_lookup_callee("Doc.updateOne"));
        assert!(!is_lookup_callee("Task.objects.create"));
        assert!(!is_lookup_callee("Task.objects.get_or_create"));
        assert!(!is_lookup_callee("Comment.create"));
    }

    #[test]
    fn pk_is_an_id_inside_route_handlers_only() {
        let helper = empty_unit();
        assert!(!is_relevant_target_subject(&plain("pk"), &helper));
        let mut route = empty_unit();
        route.kind = AnalysisUnitKind::RouteHandler;
        assert!(is_relevant_target_subject(&plain("pk"), &route));
    }
}
