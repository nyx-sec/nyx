mod common;

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::PathBuf;
use std::sync::OnceLock;

fn auth_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("auth_analysis")
}

fn scan_all_fixtures() -> &'static Vec<Diag> {
    static DIAGS: OnceLock<Vec<Diag>> = OnceLock::new();
    DIAGS.get_or_init(|| {
        let cfg = common::test_config(AnalysisMode::Full);
        nyx_scanner::scan_no_index(&auth_fixture_dir(), &cfg).expect("scan should succeed")
    })
}

fn auth_diags_for(filename: &str) -> Vec<&'static Diag> {
    scan_all_fixtures()
        .iter()
        .filter(|d| {
            d.path.contains(filename)
                && (d.id.starts_with("js.auth.")
                    || d.id.starts_with("py.auth.")
                    || d.id.starts_with("rb.auth.")
                    || d.id.starts_with("go.auth.")
                    || d.id.starts_with("java.auth.")
                    || d.id.starts_with("rs.auth."))
        })
        .collect()
}

fn auth_ids_for(filename: &str) -> Vec<String> {
    auth_diags_for(filename)
        .iter()
        .map(|diag| diag.id.clone())
        .collect()
}

fn assert_has(filename: &str, rule_id: &str) {
    assert!(
        auth_diags_for(filename)
            .iter()
            .any(|diag| diag.id == rule_id),
        "Expected {rule_id} in {filename}.\n  Got: {:?}",
        auth_ids_for(filename)
    );
}

fn assert_absent(filename: &str, rule_id: &str) {
    assert!(
        auth_diags_for(filename)
            .iter()
            .all(|diag| diag.id != rule_id),
        "Did not expect {rule_id} in {filename}.\n  Got: {:?}",
        auth_ids_for(filename)
    );
}

fn assert_no_auth_diags_for(diags: &[Diag], filename: &str) {
    let matching: Vec<_> = diags
        .iter()
        .filter(|diag| {
            diag.path.contains(filename)
                && (diag.id.starts_with("js.auth.")
                    || diag.id.starts_with("py.auth.")
                    || diag.id.starts_with("rb.auth.")
                    || diag.id.starts_with("go.auth.")
                    || diag.id.starts_with("java.auth.")
                    || diag.id.starts_with("rs.auth."))
        })
        .map(|diag| diag.id.clone())
        .collect();
    assert!(
        matching.is_empty(),
        "Did not expect auth findings in {filename}.\n  Got: {:?}",
        matching
    );
}

#[test]
fn admin_route_missing_admin_check() {
    assert_has(
        "admin_route_missing.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "admin_route_clean.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn support_impersonation_requires_admin_guard() {
    assert_has(
        "support_impersonation_missing.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn debug_session_requires_admin_guard() {
    assert_has(
        "debug_session_missing.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn koa_admin_route_missing_admin_check() {
    assert_has(
        "koa_admin_route_missing.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn koa_admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "koa_admin_route_clean.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn fastify_admin_route_missing_admin_check() {
    assert_has(
        "fastify_admin_route_missing.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn fastify_admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "fastify_admin_route_clean.js",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn scoped_read_without_membership_check() {
    assert_has("scoped_read_missing.js", "js.auth.missing_ownership_check");
}

#[test]
fn scoped_write_without_membership_check() {
    assert_has("scoped_write_missing.js", "js.auth.missing_ownership_check");
}

#[test]
fn koa_scoped_read_without_membership_check() {
    assert_has(
        "koa_scoped_read_missing.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn koa_scoped_read_with_ownership_check_is_clean() {
    assert_absent(
        "koa_scoped_read_clean.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn fastify_scoped_write_without_membership_check() {
    assert_has(
        "fastify_scoped_write_missing.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn fastify_scoped_write_with_ownership_check_is_clean() {
    assert_absent(
        "fastify_scoped_write_clean.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn koa_route_registration_noise_is_clean() {
    assert!(auth_diags_for("koa_route_registration_noise.js").is_empty());
}

#[test]
fn fastify_route_registration_noise_is_clean() {
    assert!(auth_diags_for("fastify_route_registration_noise.js").is_empty());
}

#[test]
fn self_profile_read_is_clean() {
    assert_absent("self_profile_read.js", "js.auth.missing_ownership_check");
}

#[test]
fn self_profile_update_is_clean() {
    assert_absent("self_profile_update.js", "js.auth.missing_ownership_check");
    assert_absent("self_profile_update.js", "js.auth.stale_authorization");
}

#[test]
fn current_user_listing_is_clean() {
    assert_absent(
        "dashboard_self_listing.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn auth_helper_lookup_is_clean() {
    assert_absent("membership_helper.js", "js.auth.missing_ownership_check");
}

#[test]
fn delegated_service_read_is_clean() {
    assert_absent(
        "delegated_service_read.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn related_membership_check_covers_child_reads() {
    assert_absent(
        "related_membership_check.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn workspace_job_body_id_without_check() {
    assert_has(
        "workspace_job_missing.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn service_function_without_auth_context_or_check() {
    assert_has(
        "service_missing_context.js",
        "js.auth.missing_ownership_check",
    );
}

#[test]
fn service_function_with_ownership_check_is_clean() {
    assert_absent("service_with_check.js", "js.auth.missing_ownership_check");
}

#[test]
fn stale_session_backed_mutation() {
    assert_has("stale_session_mutation.js", "js.auth.stale_authorization");
}

#[test]
fn partial_batch_authorization_detected() {
    assert_has("partial_batch.js", "js.auth.partial_batch_authorization");
}

#[test]
fn token_flow_missing_expiry_check() {
    assert_has(
        "token_missing_expiry.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn token_flow_missing_recipient_check() {
    assert_has(
        "token_missing_recipient.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn token_flow_workspace_override_detected() {
    assert_has(
        "token_workspace_override.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn token_flow_role_override_detected() {
    assert_has(
        "token_role_override.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn clean_token_acceptance_is_clean() {
    assert_absent(
        "token_clean.js",
        "js.auth.token_override_without_validation",
    );
}

#[test]
fn partial_batch_with_full_collection_authorization_is_clean() {
    assert_absent(
        "partial_batch_full_check_clean.js",
        "js.auth.partial_batch_authorization",
    );
}

#[test]
fn typescript_auth_findings_use_javascript_prefix() {
    assert_has(
        "typed_admin_route_missing.ts",
        "js.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn flask_admin_route_missing_admin_check() {
    assert_has(
        "flask_admin_route_missing.py",
        "py.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn flask_admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "flask_admin_route_clean.py",
        "py.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn flask_scoped_write_without_membership_check() {
    assert_has(
        "flask_scoped_write_missing.py",
        "py.auth.missing_ownership_check",
    );
}

#[test]
fn flask_clean_token_acceptance_is_clean() {
    assert_absent(
        "flask_token_clean.py",
        "py.auth.token_override_without_validation",
    );
}

#[test]
fn django_view_admin_route_missing_admin_check() {
    assert_has(
        "django_view_admin_missing.py",
        "py.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn django_view_admin_route_with_permission_guard_is_clean() {
    assert_absent(
        "django_view_admin_clean.py",
        "py.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn django_scoped_read_without_membership_check() {
    assert_has(
        "django_scoped_read_missing.py",
        "py.auth.missing_ownership_check",
    );
}

#[test]
fn django_cbv_admin_route_with_permission_mixin_is_clean() {
    assert_absent(
        "django_cbv_admin_clean.py",
        "py.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn django_cbv_scoped_write_without_membership_check() {
    assert_has(
        "django_cbv_scoped_write_missing.py",
        "py.auth.missing_ownership_check",
    );
}

#[test]
fn django_partial_batch_authorization_detected() {
    assert_has(
        "django_partial_batch.py",
        "py.auth.partial_batch_authorization",
    );
}

#[test]
fn django_stale_session_backed_mutation() {
    assert_has(
        "django_stale_session_mutation.py",
        "py.auth.stale_authorization",
    );
}

#[test]
fn django_token_flow_missing_expiry_check() {
    assert_has(
        "django_token_missing_expiry.py",
        "py.auth.token_override_without_validation",
    );
}

#[test]
fn django_token_flow_missing_recipient_check() {
    assert_has(
        "django_token_missing_recipient.py",
        "py.auth.token_override_without_validation",
    );
}

#[test]
fn rails_admin_route_missing_admin_check() {
    assert_has(
        "rails_admin_route_missing.rb",
        "rb.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn rails_admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "rails_admin_route_clean.rb",
        "rb.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn rails_scoped_write_without_membership_check() {
    assert_has(
        "rails_scoped_write_missing.rb",
        "rb.auth.missing_ownership_check",
    );
}

#[test]
fn rails_clean_controller_action_with_before_action_auth_is_clean() {
    assert_absent(
        "rails_clean_before_action.rb",
        "rb.auth.missing_ownership_check",
    );
}

#[test]
fn rails_partial_batch_authorization_detected() {
    assert_has(
        "rails_partial_batch.rb",
        "rb.auth.partial_batch_authorization",
    );
}

#[test]
fn rails_stale_session_backed_mutation() {
    assert_has(
        "rails_stale_session_mutation.rb",
        "rb.auth.stale_authorization",
    );
}

#[test]
fn rails_token_flow_missing_expiry_check() {
    assert_has(
        "rails_token_missing_expiry.rb",
        "rb.auth.token_override_without_validation",
    );
}

#[test]
fn rails_clean_token_acceptance_is_clean() {
    assert_absent(
        "rails_token_clean.rb",
        "rb.auth.token_override_without_validation",
    );
}

#[test]
fn sinatra_admin_route_missing_admin_check() {
    assert_has(
        "sinatra_admin_route_missing.rb",
        "rb.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn sinatra_admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "sinatra_admin_route_clean.rb",
        "rb.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn sinatra_scoped_read_without_membership_check() {
    assert_has(
        "sinatra_scoped_read_missing.rb",
        "rb.auth.missing_ownership_check",
    );
}

#[test]
fn sinatra_scoped_read_with_membership_check_is_clean() {
    assert_absent(
        "sinatra_scoped_read_clean.rb",
        "rb.auth.missing_ownership_check",
    );
}

#[test]
fn sinatra_token_flow_missing_recipient_check() {
    assert_has(
        "sinatra_token_missing_recipient.rb",
        "rb.auth.token_override_without_validation",
    );
}

#[test]
fn gin_admin_route_missing_admin_check() {
    assert_has(
        "gin_admin_route_missing.go",
        "go.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn gin_scoped_write_with_ownership_check_is_clean() {
    assert_absent(
        "gin_scoped_write_clean.go",
        "go.auth.missing_ownership_check",
    );
}

#[test]
fn gin_stale_session_backed_mutation() {
    assert_has(
        "gin_stale_session_mutation.go",
        "go.auth.stale_authorization",
    );
}

#[test]
fn echo_admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "echo_admin_route_clean.go",
        "go.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn echo_partial_batch_authorization_detected() {
    assert_has(
        "echo_partial_batch.go",
        "go.auth.partial_batch_authorization",
    );
}

#[test]
fn echo_token_flow_missing_recipient_check() {
    assert_has(
        "echo_token_missing_recipient.go",
        "go.auth.token_override_without_validation",
    );
}

#[test]
fn spring_admin_route_missing_admin_check() {
    assert_has(
        "spring_admin_route_missing.java",
        "java.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn spring_admin_route_with_annotation_guard_is_clean() {
    assert_absent(
        "spring_admin_route_clean.java",
        "java.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn spring_scoped_read_without_membership_check() {
    assert_has(
        "spring_scoped_read_missing.java",
        "java.auth.missing_ownership_check",
    );
}

#[test]
fn axum_admin_route_missing_admin_check() {
    assert_has(
        "axum_admin_route_missing.rs",
        "rs.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn axum_admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "axum_admin_route_clean.rs",
        "rs.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn axum_partial_batch_authorization_detected() {
    assert_has(
        "axum_partial_batch.rs",
        "rs.auth.partial_batch_authorization",
    );
}

#[test]
fn actix_scoped_write_without_membership_check() {
    assert_has(
        "actix_scoped_write_missing.rs",
        "rs.auth.missing_ownership_check",
    );
}

#[test]
fn hashmap_local_noise_is_clean() {
    // std::collections method calls on locally-constructed
    // HashMap/HashSet bindings should not be treated as
    // authorization-relevant Read/Mutation operations.
    assert_absent("hashmap_local_noise.rs", "rs.auth.missing_ownership_check");
}

#[test]
fn row_ownership_equality_is_clean() {
    // `if owner_id != user.id { return ... }` is a row-level
    // ownership check, both the row-fetching call and any downstream
    // uses of the row's fields should be considered authorized.
    assert_absent(
        "row_ownership_equality.rs",
        "rs.auth.missing_ownership_check",
    );
}

#[test]
fn row_ownership_no_early_exit_flags() {
    // Regression guard: equality check without an early exit has no
    // effect, so the downstream mutation should still flag.
    assert_has(
        "row_ownership_no_early_exit.rs",
        "rs.auth.missing_ownership_check",
    );
}

#[test]
fn helper_scoped_params_is_clean() {
    // A library helper whose internal work is `result.insert(..)`
    // on a locally-constructed HashSet is not a sink, the call is
    // classified as non-sink because the receiver is the locally-bound
    // collection.
    assert_absent("helper_scoped_params.rs", "rs.auth.missing_ownership_check");
}

#[test]
fn self_scoped_user_is_clean() {
    // `let user = auth::require_auth(..).await?` binds the
    // authenticated caller, so `user.id` passed to a helper is self-
    // referential rather than a foreign scoped id.
    assert_absent("self_scoped_user.rs", "rs.auth.missing_ownership_check");
}

#[test]
fn true_positive_missing_check_flags() {
    // Positive control: an authenticated handler that deletes a doc
    // and publishes against a group without any ownership/membership
    // check, must still flag.
    assert_has(
        "true_positive_missing_check.rs",
        "rs.auth.missing_ownership_check",
    );
}

#[test]
fn helper_no_auth_lift_still_flags() {
    // Regression guard: a helper that doesn't auth-check its
    // parameter must NOT have a synthetic AuthCheck synthesised at
    // its call site.
    assert_has("helper_no_auth_lift.rs", "rs.auth.missing_ownership_check");
}

#[test]
fn transitive_helper_is_clean() {
    // `validate_target(&db, group_id, user.id)` is a helper that
    // internally calls `authz::require_group_member` against
    // `group_id`. Helper-summary lifting should synthesise an
    // AuthCheck at the handler's call site covering `group_id`, so
    // the subsequent `db.exec("INSERT INTO comments …", &[group_id])`
    // MUST NOT flag.
    assert_absent("transitive_helper.rs", "rs.auth.missing_ownership_check");
}

#[test]
fn cross_file_helper_is_clean() {
    // `require_owner(&user, &row)` is declared in
    // `cross_file_helper_authz.rs` and called from
    // `cross_file_helper_handler.rs`. Cross-file helper-summary
    // lifting must synthesise an AuthCheck at the handler's call
    // site covering `row`, so the downstream `db.update(..)` must
    // NOT flag as `rs.auth.missing_ownership_check`.
    assert_absent(
        "cross_file_helper_handler.rs",
        "rs.auth.missing_ownership_check",
    );
    // The helper itself is a free function returning `Result<(), ()>`;
    // it performs no sensitive operation and should produce no auth
    // findings.
    assert_absent(
        "cross_file_helper_authz.rs",
        "rs.auth.missing_ownership_check",
    );
}

#[test]
fn sql_no_acl_join_flags() {
    // Regression guard: a JOIN against a non-ACL table (`audit_log`,
    // not in the configured ACL list) does NOT prove caller ownership
    // even when the WHERE clause names `user_id`.  The downstream
    // realtime publish must still flag.
    assert_has(
        "sql_no_acl_join_flags.rs",
        "rs.auth.missing_ownership_check",
    );
}

#[test]
fn sql_join_acl_is_clean() {
    // A SELECT that JOINs through the configured `group_members`
    // ACL table and pins rows via `WHERE gm.user_id = ?1` is auth-gated.
    // Downstream uses of the returned columns (`group_id` here) are
    // covered by the synthesised SQL `AuthCheck`, so the realtime
    // publish call MUST NOT flag.
    assert_absent("sql_join_acl.rs", "rs.auth.missing_ownership_check");
}

#[test]
fn db_connection_type_inferred_is_clean() {
    // `let conn = rusqlite::Connection::open(..).unwrap();` is
    // inferred as a `DatabaseConnection` via SSA `constructor_type`
    // (through `peel_identity_suffix`).  The handler logs the caller's
    // own id; no foreign scoped id reaches the sink, so the ownership
    // gate has nothing to flag, the type-facts refinement must not
    // introduce a false positive here.
    assert_absent(
        "db_connection_type_inferred.rs",
        "rs.auth.missing_ownership_check",
    );
}

#[test]
fn actix_admin_route_with_admin_guard_is_clean() {
    assert_absent(
        "actix_admin_route_clean.rs",
        "rs.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn rocket_admin_route_with_guard_is_clean() {
    assert_absent(
        "rocket_admin_route_clean.rs",
        "rs.auth.admin_route_missing_admin_check",
    );
}

#[test]
fn rocket_stale_session_backed_mutation() {
    assert_has(
        "rocket_stale_session_mutation.rs",
        "rs.auth.stale_authorization",
    );
}

#[test]
fn rocket_token_flow_missing_recipient_check() {
    assert_has(
        "rocket_token_missing_recipient.rs",
        "rs.auth.token_override_without_validation",
    );
}

#[test]
fn generic_admin_route_check_is_consistent_across_languages() {
    for (filename, rule_id) in [
        (
            "admin_route_missing.js",
            "js.auth.admin_route_missing_admin_check",
        ),
        (
            "flask_admin_route_missing.py",
            "py.auth.admin_route_missing_admin_check",
        ),
        (
            "rails_admin_route_missing.rb",
            "rb.auth.admin_route_missing_admin_check",
        ),
        (
            "gin_admin_route_missing.go",
            "go.auth.admin_route_missing_admin_check",
        ),
        (
            "spring_admin_route_missing.java",
            "java.auth.admin_route_missing_admin_check",
        ),
        (
            "axum_admin_route_missing.rs",
            "rs.auth.admin_route_missing_admin_check",
        ),
    ] {
        assert_has(filename, rule_id);
    }
}

#[test]
fn generic_ownership_check_is_consistent_across_languages() {
    for (filename, rule_id) in [
        ("scoped_write_missing.js", "js.auth.missing_ownership_check"),
        (
            "django_scoped_read_missing.py",
            "py.auth.missing_ownership_check",
        ),
        (
            "rails_scoped_write_missing.rb",
            "rb.auth.missing_ownership_check",
        ),
        (
            "spring_scoped_read_missing.java",
            "java.auth.missing_ownership_check",
        ),
        (
            "actix_scoped_write_missing.rs",
            "rs.auth.missing_ownership_check",
        ),
    ] {
        assert_has(filename, rule_id);
    }
}

#[test]
fn auth_analysis_runs_in_ast_mode() {
    let cfg = common::test_config(AnalysisMode::Ast);
    let diags = nyx_scanner::scan_no_index(&auth_fixture_dir(), &cfg).expect("scan should succeed");
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("scoped_write_missing.js")
                && diag.id == "js.auth.missing_ownership_check"
        }),
        "expected AST mode to emit js.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("koa_scoped_read_missing.js")
                && diag.id == "js.auth.missing_ownership_check"
        }),
        "expected AST mode to emit Koa js.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("fastify_scoped_write_missing.js")
                && diag.id == "js.auth.missing_ownership_check"
        }),
        "expected AST mode to emit Fastify js.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("flask_scoped_write_missing.py")
                && diag.id == "py.auth.missing_ownership_check"
        }),
        "expected AST mode to emit Flask py.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("django_cbv_scoped_write_missing.py")
                && diag.id == "py.auth.missing_ownership_check"
        }),
        "expected AST mode to emit Django py.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("rails_scoped_write_missing.rb")
                && diag.id == "rb.auth.missing_ownership_check"
        }),
        "expected AST mode to emit Rails rb.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("sinatra_scoped_read_missing.rb")
                && diag.id == "rb.auth.missing_ownership_check"
        }),
        "expected AST mode to emit Sinatra rb.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("gin_admin_route_missing.go")
                && diag.id == "go.auth.admin_route_missing_admin_check"
        }),
        "expected AST mode to emit Gin go.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("echo_partial_batch.go")
                && diag.id == "go.auth.partial_batch_authorization"
        }),
        "expected AST mode to emit Echo go.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("spring_scoped_read_missing.java")
                && diag.id == "java.auth.missing_ownership_check"
        }),
        "expected AST mode to emit Spring java.auth findings"
    );
    assert!(
        diags.iter().any(|diag| {
            diag.path.contains("actix_scoped_write_missing.rs")
                && diag.id == "rs.auth.missing_ownership_check"
        }),
        "expected AST mode to emit Rust rs.auth findings"
    );
}

#[test]
fn auth_analysis_does_not_run_in_cfg_mode() {
    let cfg = common::test_config(AnalysisMode::Cfg);
    let diags = nyx_scanner::scan_no_index(&auth_fixture_dir(), &cfg).expect("scan should succeed");
    assert!(
        diags.iter().all(|diag| !diag.id.starts_with("js.auth.")),
        "CFG mode should not emit js.auth findings"
    );
    assert!(
        diags.iter().all(|diag| !diag.id.starts_with("py.auth.")),
        "CFG mode should not emit py.auth findings"
    );
    assert!(
        diags.iter().all(|diag| !diag.id.starts_with("rb.auth.")),
        "CFG mode should not emit rb.auth findings"
    );
    assert!(
        diags.iter().all(|diag| !diag.id.starts_with("go.auth.")),
        "CFG mode should not emit go.auth findings"
    );
    assert!(
        diags.iter().all(|diag| !diag.id.starts_with("java.auth.")),
        "CFG mode should not emit java.auth findings"
    );
    assert!(
        diags.iter().all(|diag| !diag.id.starts_with("rs.auth.")),
        "CFG mode should not emit rs.auth findings"
    );
    // Per-file checks: CFG mode must not produce any *.auth.* finding on
    // each fixture file. We filter by id prefix (not path-only) so that
    // genuine taint flows the engine catches in CFG mode (e.g.
    // `ctx.body = { project }` data exfil after a query) don't trip the
    // assertion. The earlier global asserts above already cover the auth
    // rule prefixes; these per-file checks pin the intent that auth
    // analysis is fully gated on AST mode.
    let auth_in_file = |needle: &str| {
        diags
            .iter()
            .any(|d| d.path.contains(needle) && d.id.contains(".auth."))
    };
    assert!(
        !auth_in_file("koa_scoped_read_missing.js"),
        "CFG mode should not emit Koa auth-analysis findings"
    );
    assert!(
        !auth_in_file("fastify_scoped_write_missing.js"),
        "CFG mode should not emit Fastify auth-analysis findings"
    );
    assert!(
        !auth_in_file("flask_scoped_write_missing.py"),
        "CFG mode should not emit Flask auth-analysis findings"
    );
    assert!(
        !auth_in_file("django_cbv_scoped_write_missing.py"),
        "CFG mode should not emit Django auth-analysis findings"
    );
    assert!(
        !auth_in_file("rails_scoped_write_missing.rb"),
        "CFG mode should not emit Rails auth-analysis findings"
    );
    assert!(
        !auth_in_file("sinatra_scoped_read_missing.rb"),
        "CFG mode should not emit Sinatra auth-analysis findings"
    );
    assert!(
        !auth_in_file("gin_admin_route_missing.go"),
        "CFG mode should not emit Gin auth-analysis findings"
    );
    assert!(
        !auth_in_file("echo_partial_batch.go"),
        "CFG mode should not emit Echo auth-analysis findings"
    );
    assert!(
        !auth_in_file("spring_scoped_read_missing.java"),
        "CFG mode should not emit Spring auth-analysis findings"
    );
    assert!(
        !auth_in_file("actix_scoped_write_missing.rs"),
        "CFG mode should not emit Rust auth-analysis findings"
    );
}

/// Real-repo precision (2026-04-27, JS slice 2): TRPC handler
/// Options-typed parameter exempts `ctx.user.<id-like>` subjects from
/// `js.auth.missing_ownership_check` via the dynamic
/// `self_scoped_session_bases` set.
#[test]
fn trpc_ctx_user_options_does_not_flag() {
    assert_absent(
        "trpc_ctx_user_options.ts",
        "js.auth.missing_ownership_check",
    );
}

/// Real-repo precision (2026-04-27, JS slice 2): destructured
/// `const { user } = ctx.session` recognises the local as
/// self-actor; `user.id` does not flag.
#[test]
fn destructured_session_user_does_not_flag() {
    assert_absent(
        "destructured_session_user.ts",
        "js.auth.missing_ownership_check",
    );
}

/// Real-repo precision (2026-04-27, hugo follow-up): a Go method's
/// own receiver (`func (c *Cache) ...`) seeds `non_sink_vars`, so
/// `c.foo(...)` and `c.field.bar(...)` route through
/// `SinkClass::InMemoryLocal` and don't fire missing-ownership.
#[test]
fn go_self_method_receiver_does_not_flag() {
    assert_absent(
        "go_self_method_receiver.go",
        "go.auth.missing_ownership_check",
    );
}

#[test]
fn auth_analysis_does_not_run_in_taint_mode() {
    let cfg = common::test_config(AnalysisMode::Taint);
    let diags = nyx_scanner::scan_no_index(&auth_fixture_dir(), &cfg).expect("scan should succeed");
    for filename in [
        "admin_route_missing.js",
        "typed_admin_route_missing.ts",
        "flask_admin_route_missing.py",
        "rails_admin_route_missing.rb",
        "gin_admin_route_missing.go",
        "spring_admin_route_missing.java",
        "axum_admin_route_missing.rs",
    ] {
        assert_no_auth_diags_for(&diags, filename);
    }
}
