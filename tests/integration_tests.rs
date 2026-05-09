mod common;

use common::{assert_no_findings, scan_fixture_dir, validate_expectations};
use nyx_scanner::utils::config::AnalysisMode;
use std::collections::HashSet;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// ── Per-fixture tests ──────────────────────────────────────────────────────

#[test]
fn rust_web_app() {
    let dir = fixture_path("rust_web_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn rust_framework_rules() {
    let dir = fixture_path("rust_framework_rules");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn rust_module_path_resolution() {
    // Two modules define `pub fn validate(&str) -> String` with the same arity.
    // `main.rs` has `use crate::auth::token::validate;` and calls `validate(&cmd)`.
    // A correct use-map driven resolver must target `auth::token::validate`
    // (pass-through sanitizer) and NOT `auth::session::validate` (shell sink);
    // the expectations forbid any taint finding on main.rs.
    let dir = fixture_path("rust_module_path_resolution");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn express_app() {
    let dir = fixture_path("express_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn koa_app() {
    let dir = fixture_path("koa_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn fastify_app() {
    let dir = fixture_path("fastify_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_integration() {
    let dir = fixture_path("auth_analysis_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_frameworks_integration() {
    let dir = fixture_path("auth_analysis_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_noise_frameworks() {
    let dir = fixture_path("auth_analysis_noise_frameworks");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_python_frameworks_integration() {
    let dir = fixture_path("auth_analysis_python_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_ruby_frameworks_integration() {
    let dir = fixture_path("auth_analysis_ruby_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_go_java_frameworks_integration() {
    let dir = fixture_path("auth_analysis_go_java_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_rust_frameworks_integration() {
    let dir = fixture_path("auth_analysis_rust_frameworks_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_admin_multilang_integration() {
    let dir = fixture_path("auth_analysis_admin_multilang_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn auth_analysis_ownership_multilang_integration() {
    let dir = fixture_path("auth_analysis_ownership_multilang_integration");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn flask_app() {
    let dir = fixture_path("flask_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn go_server() {
    let dir = fixture_path("go_server");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn c_utils() {
    let dir = fixture_path("c_utils");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn java_service() {
    let dir = fixture_path("java_service");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn mixed_project() {
    let dir = fixture_path("mixed_project");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_taint() {
    let dir = fixture_path("cross_file_taint");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_ssa_propagation() {
    let dir = fixture_path("cross_file_ssa_propagation");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_ssa_source() {
    let dir = fixture_path("cross_file_ssa_source");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_ssa_sanitizer() {
    let dir = fixture_path("cross_file_ssa_sanitizer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── Cross-file param sink precision ───────────────────────────────────────

#[test]
fn cross_file_param_sink_precision() {
    let dir = fixture_path("cross_file_param_sink_precision");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_mixed_cap_sink() {
    let dir = fixture_path("cross_file_mixed_cap_sink");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Two different sinks on the same line (SQL + SHELL) must produce two
/// distinct taint findings. Regression guard for the dedup fix where
/// the grouping key includes sink capability bits, so `sink_sql(x);
/// sink_shell(x);` no longer collapses into a single finding.
#[test]
fn dedup_same_line_different_sinks() {
    let dir = fixture_path("dedup_same_line_different_sinks");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    // Inspect the specific line where the two sinks live. Both findings
    // must exist, and must carry different resolved sink cap bits.
    let taint_on_target_line: Vec<&nyx_scanner::commands::scan::Diag> = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow") && d.line == 10)
        .collect();
    assert!(
        taint_on_target_line.len() >= 2,
        "expected at least 2 taint findings on line 10 (dedup must not collapse \
         different sinks), got {}: {:#?}",
        taint_on_target_line.len(),
        taint_on_target_line
            .iter()
            .map(|d| format!(
                "{}:{} [caps={}]",
                d.path,
                d.line,
                d.evidence.as_ref().map(|e| e.sink_caps).unwrap_or(0)
            ))
            .collect::<Vec<_>>()
    );
    let caps: HashSet<u32> = taint_on_target_line
        .iter()
        .map(|d| d.evidence.as_ref().map(|e| e.sink_caps).unwrap_or(0))
        .collect();
    assert!(
        caps.len() >= 2,
        "expected findings on line 10 to carry distinct sink_caps, got {:?}",
        caps
    );
}

// ── Multi-arg validator target narrowing ────────────────────────────────

/// `validate(x, 100)` must narrow validation to `x`, so the tainted
/// `x` flowing to `os.system(x)` on the true branch is correctly silenced.
/// Regression guard for the existing target-extraction path.
#[test]
fn predicate_multi_arg_validator_tainted() {
    let dir = fixture_path("predicate_multi_arg_validator_tainted");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// `validate(limit, x)` validates `limit`, not `x`. Tainted `x`
/// still flows to `os.system(x)` and the finding must fire. Regression guard
/// against upstream code marking every `condition_var` as validated when
/// target extraction narrows to a non-tainted var.
#[test]
fn predicate_multi_arg_validator_wrong() {
    let dir = fixture_path("predicate_multi_arg_validator_wrong");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── Gated-sink dynamic activation conservatism ────────────────────────────

/// `setAttribute(attr, val)` with a dynamic first arg returns the
/// ALL_ARGS_PAYLOAD sentinel, so sink scanning expands to every positional
/// arg, a tainted attribute name is itself a vulnerability path. Expects
/// at least two findings (one per call where either arg is tainted).
#[test]
fn gated_sink_dynamic_activation() {
    let dir = fixture_path("gated_sink_dynamic_activation");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── SCC SSA summary refinement ────────────────────────────────────────────

#[test]
fn cross_file_scc_ssa() {
    let dir = fixture_path("cross_file_scc_ssa");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_scc_convergence() {
    let dir = fixture_path("cross_file_scc_convergence");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_symex_body() {
    let dir = fixture_path("cross_file_symex_body");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn cross_file_symex_js() {
    let dir = fixture_path("cross_file_symex_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── New multi-file fixtures ────────────────────────────────────────────────

// --- True positives ---------------------------------------------------------

/// Go: HTTP handler in handler.go passes r.FormValue("cmd") to runCommand()
/// defined in executor.go, which calls exec.Command, shell execution sink.
#[test]
fn cross_file_go_handler_exec() {
    let dir = fixture_path("cross_file_go_handler_exec");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Java: UserController.java reads getParameter("name") and passes it to
/// UserRepository.findByName(), which concatenates it into executeQuery().
/// Cross-file taint propagates via param_to_sink in the resolved summary.
#[test]
fn cross_file_java_sqli() {
    let dir = fixture_path("cross_file_java_sqli");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// TypeScript: router.ts reads req.query.url and forwards it to
/// fetchRemote() in httpClient.ts, which passes it to fetch(), SSRF.
#[test]
fn cross_file_ts_ssrf() {
    let dir = fixture_path("cross_file_ts_ssrf");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript: source.js exports getInput(data); app.js destructures it under
/// the alias fetchUserCmd and passes req.query.cmd through it to execSync.
/// Import alias resolution maps fetchUserCmd → getInput for cross-file taint.
#[test]
fn cross_file_js_aliased_import() {
    let dir = fixture_path("cross_file_js_aliased_import");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript: req.body.returnTo (inline source member expression in call arg)
/// flows through cross-file safeRedirect() passthrough to res.redirect() sink.
/// Exercises source node pre-emission for source member expressions nested
/// directly inside sink call arguments.
#[test]
fn cross_file_js_redirect() {
    let dir = fixture_path("cross_file_js_redirect");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript: req.query.q flows through cross-file globalSearch() which
/// concatenates the param into raw SQL and passes it to db.query().
/// Tests cross-file param_to_sink propagation for SQL injection.
#[test]
fn cross_file_js_sqli() {
    let dir = fixture_path("cross_file_js_sqli");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python: 3-file chain, os.environ in input_reader.py → passthrough in
/// transform.py → subprocess.call in executor.py.  Taint must survive two
/// inter-file hops with no sanitisation.
#[test]
fn cross_file_py_nested_chain() {
    let dir = fixture_path("cross_file_py_nested_chain");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python: object attribute carries taint across files, JobRequest.cmd is
/// populated from os.environ in models.py; handler.py reads req.cmd and
/// passes it to subprocess.call.
#[test]
fn cross_file_py_object_field() {
    let dir = fixture_path("cross_file_py_object_field");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// --- True negatives ---------------------------------------------------------

/// Python: shlex.quote (SHELL_ESCAPE sanitiser) is defined in shell_utils.py
/// and called from handler.py before subprocess.call, no finding expected.
#[test]
fn cross_file_py_shlex_sanitizer() {
    let dir = fixture_path("cross_file_py_shlex_sanitizer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript: xss() HTML sanitiser defined in security.js is applied before
/// document.write in app.js, no taint-unsanitised-flow expected.
#[test]
fn cross_file_js_html_sanitized() {
    let dir = fixture_path("cross_file_js_html_sanitized");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python: constants.py returns a hardcoded string literal; runner.py uses it
/// in subprocess.call, no taint source exists, so no finding expected.
#[test]
fn cross_file_py_const_passthrough() {
    let dir = fixture_path("cross_file_py_const_passthrough");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Go: validation.go converts r.FormValue("id") with strconv.Atoi (Cap::all
/// sanitiser) before handler.go calls db.QueryRow, no SQL taint expected.
#[test]
fn cross_file_go_int_validated() {
    let dir = fixture_path("cross_file_go_int_validated");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// --- Near-miss cases --------------------------------------------------------

/// Python near miss, TRUE POSITIVE:
/// html_guard.py applies html.escape (HTML_ESCAPE cap) before a SQL
/// concatenation in app.py.  The HTML sanitiser does not cover SQL_QUERY
/// capability, so the flow is still vulnerable, Nyx should detect it.
/// Tests that the engine does not over-sanitise with the wrong cap type.
#[test]
fn cross_file_near_miss_wrong_sanitizer() {
    let dir = fixture_path("cross_file_near_miss_wrong_sanitizer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JavaScript near miss, TRUE NEGATIVE:
/// session.js stores user input in `lastUser` but getDefaultQuery() returns
/// the constant `defaultQuery`.  app.js passes the result to pool.query().
/// A coarse analysis might falsely flag this; a precise one should not.
/// Tests that the engine does not conflate distinct module-level variables.
#[test]
fn cross_file_near_miss_field_isolation() {
    let dir = fixture_path("cross_file_near_miss_field_isolation");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Same-file identity collision, ADVERSARIAL.
/// `runTask` is defined as a free function (shell-exec sink) AND as a
/// method on multiple classes in the same file with conflicting
/// security behaviours.  A bare `runTask(tainted)` top-level call MUST
/// resolve to the free function (its summary carries a SHELL_ESCAPE
/// sink), the pre-fix resolver returned Ambiguous for this call and
/// silently dropped the finding.  Regression guard for the bare-call
/// free-function preference (resolve_callee step 5.5).
#[test]
fn same_name_collisions_js() {
    let dir = fixture_path("same_name_collisions_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── New sink coverage fixtures ────────────────────────────────────────────

/// JS: execAsync wraps child_process.exec; user input flows through the
/// wrapper to the inner exec call, SHELL_ESCAPE finding expected.
#[test]
fn exec_async_wrapper() {
    let dir = fixture_path("exec_async_wrapper");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JS: res.download(path.join(root, req.query.path)), path traversal
/// via Express res.download FILE_IO sink.
#[test]
fn path_traversal_download() {
    let dir = fixture_path("path_traversal_download");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JS: md5(password) and crypto.createHash("sha1"), weak hash patterns.
#[test]
fn weak_hash_password() {
    let dir = fixture_path("weak_hash_password");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// JS: hardcoded secret/password in object literal.
#[test]
fn hardcoded_secret() {
    let dir = fixture_path("hardcoded_secret");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── Cross-cutting tests ───────────────────────────────────────────────────

#[test]
fn ast_only_mode_excludes_taint() {
    let dir = fixture_path("rust_web_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Ast);

    assert_no_findings(&diags, "taint-");
    assert_no_findings(&diags, "cfg-");
}

#[test]
fn taint_only_mode_excludes_ast() {
    let dir = fixture_path("rust_web_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Taint);

    // Taint mode should not produce AST-only pattern findings
    assert_no_findings(&diags, "rs.quality.unwrap");
    assert_no_findings(&diags, "rs.quality.expect");
}

#[test]
fn dedup_no_double_report() {
    let dir = fixture_path("rust_web_app");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // The same (path, line, col, rule_id) tuple should never appear twice.
    // Different rule IDs at the same location are fine (e.g., taint + cfg-auth-gap).
    let mut seen: HashSet<(String, usize, usize, String)> = HashSet::new();
    let mut exact_dupes = Vec::new();
    for d in &diags {
        let key = (d.path.clone(), d.line, d.col, d.id.clone());
        if !seen.insert(key) {
            exact_dupes.push(format!("{}:{}:{} {}", d.path, d.line, d.col, d.id));
        }
    }
    assert!(
        exact_dupes.is_empty(),
        "Exact duplicate findings (same location + rule ID) found ({}):\n  {}",
        exact_dupes.len(),
        exact_dupes.join("\n  ")
    );
}

#[test]
fn mixed_project_multi_language() {
    let dir = fixture_path("mixed_project");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Findings should span at least 2 different file extensions
    let extensions: HashSet<&str> = diags
        .iter()
        .filter_map(|d| {
            std::path::Path::new(&d.path)
                .extension()
                .and_then(|e| e.to_str())
        })
        .collect();

    assert!(
        extensions.len() >= 2,
        "Expected findings from >= 2 language file extensions, got: {:?}",
        extensions
    );

    // Total findings >= 3 across languages
    assert!(
        diags.len() >= 3,
        "Expected >= 3 total findings in mixed project, got {}",
        diags.len()
    );
}

/// JS: throw in error-check branch should be recognized as a terminator,
/// suppressing cfg-error-fallthrough false positives.
#[test]
fn error_throw_terminates() {
    let dir = fixture_path("error_throw_terminates");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── Binary smoke test ──────────────────────────────────────────────────────

#[test]
fn binary_json_output() {
    let fixture = fixture_path("rust_web_app");
    #[allow(deprecated)]
    let cmd = assert_cmd::Command::cargo_bin("nyx")
        .expect("nyx binary should exist")
        .arg("scan")
        .arg(fixture.to_str().unwrap())
        .arg("--no-index")
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to execute nyx binary");

    assert!(
        cmd.status.success(),
        "nyx scan exited with non-zero status: {:?}\nstderr: {}",
        cmd.status,
        String::from_utf8_lossy(&cmd.stderr)
    );

    let stdout = String::from_utf8_lossy(&cmd.stdout);
    // Find the JSON array in stdout (config notes and "Finished" surround it)
    let json_start = stdout.find('[').expect("Expected JSON array in stdout");
    let json_end = stdout.rfind(']').expect("Expected closing bracket in JSON") + 1;
    let json_str = &stdout[json_start..json_end];
    let parsed: Vec<serde_json::Value> =
        serde_json::from_str(json_str).expect("stdout should contain valid JSON array");

    assert!(
        !parsed.is_empty(),
        "Expected at least 1 finding in JSON output"
    );
}

// ── EJS / config / debug endpoint fixtures ──────────────────────────────────

/// EJS template: detects unescaped `<%- query %>` and `<%- resultHtml %>`
/// but not `<%- include(...) %>` or `<%= safe %>`.
#[test]
fn ejs_xss() {
    let dir = fixture_path("ejs_xss");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Express session config: detects httpOnly: false, secure: false,
/// sameSite: "none", and hardcoded secret.
#[test]
fn insecure_session_config() {
    let dir = fixture_path("insecure_session_config");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Debug endpoint: process.env → res.json() should be caught by taint.
#[test]
fn debug_endpoint() {
    let dir = fixture_path("debug_endpoint");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Internal path-prefix redirects should be suppressed; open redirects should fire.
#[test]
fn internal_redirect_taint() {
    let dir = fixture_path("internal_redirect_taint");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Route registration methods (router.get/post) and session lifecycle should
/// not propagate taint or generate findings.
#[test]
fn route_registration_noise() {
    let dir = fixture_path("route_registration_noise");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

#[test]
fn route_registration_noise_frameworks() {
    let dir = fixture_path("route_registration_noise_frameworks");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Dynamic HTTP module dispatch: lib = require("http"), lib.request(url)
/// should be resolved as SSRF sink via module alias tracking.
#[test]
fn dynamic_dispatch_ssrf() {
    let dir = fixture_path("dynamic_dispatch_ssrf");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Cross-file info leak: service returns process.env data (source-independent
/// taint), caller passes to res.json() sink.
#[test]
fn cross_file_info_leak() {
    let dir = fixture_path("cross_file_info_leak");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python `subprocess.run(cmd, shell=True)` where `cmd` is user-controlled ,
/// the multi-kwarg SHELL_ESCAPE gate activates.  Validates end-to-end wiring
/// of `CallMeta.kwargs` through `classify_gated_sink`'s `dangerous_kwargs`
/// path (presence-aware shell=True → dangerous).
#[test]
fn python_subprocess_shell_true_tainted() {
    let dir = fixture_path("python_subprocess_shell_true");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python `subprocess.run([cmd], shell=False)`, shell kwarg present but not
/// dangerous.  The gate must not fire and no taint flow should be reported.
#[test]
fn python_subprocess_shell_false_safe() {
    let dir = fixture_path("python_subprocess_shell_false_safe");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python `subprocess.run([cmd])`, no shell kwarg (default shell=False).
/// The gate must not fire and no taint flow should be reported.
#[test]
fn python_subprocess_shell_default_safe() {
    let dir = fixture_path("python_subprocess_shell_default_safe");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

// ── FP guard fixtures ─────────────────────────────────────────────────────
//
// Each fixture below is a small source file exercising a pattern where
// the analyser must NOT emit a taint-unsanitised-flow (with the single
// exception of `fp_guard_call_site_specialization_py`, which requires
// one finding only on the tainted call-site).  The fixtures are grouped
// into five categories so a single regression cannot silently erase a
// whole category's coverage.

/// FP guard, sanitizer edge case: hand-rolled HTML escape covers
/// document.write sink.
#[test]
fn fp_guard_sanitizer_html_escape_js() {
    let dir = fixture_path("fp_guards/sanitizer_html_escape_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, sanitizer edge case: shlex.quote with shell metacharacters.
#[test]
fn fp_guard_sanitizer_shlex_quote_py() {
    let dir = fixture_path("fp_guards/sanitizer_shlex_quote_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, sanitizer edge case: encodeURIComponent on a URL argument.
#[test]
fn fp_guard_sanitizer_url_encode_js() {
    let dir = fixture_path("fp_guards/sanitizer_url_encode_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, sanitizer edge case: multi-step chain (`.strip()` then
/// `shlex.quote`) preserves the final SHELL_ESCAPE cap.
#[test]
fn fp_guard_sanitizer_multi_step_py() {
    let dir = fixture_path("fp_guards/sanitizer_multi_step_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, type-driven suppression: `int()` parse of env port
/// before `socket.bind`.
#[test]
fn fp_guard_types_int_port_py() {
    let dir = fixture_path("fp_guards/types_int_port_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, type-driven suppression: `int()` parse guarantees SQL
/// concat is decimal-only.
#[test]
fn fp_guard_types_int_id_sql_py() {
    let dir = fixture_path("fp_guards/types_int_id_sql_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, type-driven suppression: Go `strconv.Atoi` covers
/// Cap::all on the resulting int.
#[test]
fn fp_guard_types_parse_int_go() {
    let dir = fixture_path("fp_guards/types_parse_int_go");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, type-driven suppression: bool comparison never reaches
/// a string-context sink.
#[test]
fn fp_guard_types_bool_flag_py() {
    let dir = fixture_path("fp_guards/types_bool_flag_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, struct-field isolation: JS object `safeField` used at
/// sink, tainted `unsafeField` unused.
#[test]
fn fp_guard_fields_object_isolation_js() {
    let dir = fixture_path("fp_guards/fields_object_isolation_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, struct-field isolation: Python class attributes, only
/// the hardcoded attribute flows to the sink.
#[test]
fn fp_guard_fields_class_attr_py() {
    let dir = fixture_path("fp_guards/fields_class_attr_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, struct-field isolation: Python dict keys, only the
/// constant key flows to the sink.
#[test]
fn fp_guard_fields_dict_key_py() {
    let dir = fixture_path("fp_guards/fields_dict_key_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, struct-field isolation: nested JS objects, sibling path
/// isolation at `cfg.auth.*`.
#[test]
fn fp_guard_fields_nested_object_js() {
    let dir = fixture_path("fp_guards/fields_nested_object_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, cross-call-site specialization: same callee, two callers
/// (one tainted, one constant).  Required finding only from the
/// tainted caller.
#[test]
fn fp_guard_call_site_specialization_py() {
    let dir = fixture_path("fp_guards/call_site_specialization_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, cross-call-site specialization: JS helper called with a
/// literal SQL string must not inherit taint.
#[test]
fn fp_guard_call_site_specialization_js() {
    let dir = fixture_path("fp_guards/call_site_specialization_js");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, cross-call-site specialization: helper called with a
/// shlex.quote-sanitised value, inline analysis sees SHELL_ESCAPE cap.
#[test]
fn fp_guard_call_site_sanitized_caller_py() {
    let dir = fixture_path("fp_guards/call_site_sanitized_caller_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, cross-call-site specialization: polymorphic caller
/// (int branch and constant branch), neither carries a payload.
#[test]
fn fp_guard_call_site_polymorphic_py() {
    let dir = fixture_path("fp_guards/call_site_polymorphic_py");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, framework-safe pattern: Rails `sanitize` before render.
#[test]
fn fp_guard_framework_rails_sanitize() {
    let dir = fixture_path("fp_guards/framework_rails_sanitize");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, framework-safe pattern: Flask + MarkupSafe `escape`.
#[test]
fn fp_guard_framework_flask_escape() {
    let dir = fixture_path("fp_guards/framework_flask_escape");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, framework-safe pattern: Express `res.json` with a
/// constant payload is not an XSS sink.
#[test]
fn fp_guard_framework_express_res_json() {
    let dir = fixture_path("fp_guards/framework_express_res_json");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, FastAPI `dependencies=[Depends(requires_access_*)]`
/// route-level guard short-circuits `auth_check_covers_subject` so
/// the handler body's path-param ORM calls and row-variable method
/// calls do not trip `py.auth.missing_ownership_check`.  Pinned by
/// the `is_route_level` flag on `AuthCheck` plus the kind-aware
/// `function_params_route_handler` that includes id-like Python
/// typed params (`dag_id: str`) in `unit.params`.
#[test]
fn fp_guard_framework_fastapi_route_level_auth() {
    let dir = fixture_path("fp_guards/framework_fastapi_route_level_auth");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, framework-safe pattern: JDBC PreparedStatement.setString
/// covers SQL_QUERY on the bound parameter.
#[test]
fn fp_guard_framework_prepared_stmt_java() {
    let dir = fixture_path("fp_guards/framework_prepared_stmt_java");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, JPA parameterised execute chain
/// (`em.createQuery(LITERAL).setParameter(...).executeUpdate()`).
/// Pinned from a 150-finding cluster in keycloak's
/// `JpaEventStoreProvider.java`.  The engine walks the receiver chain
/// from the zero-arg `.executeUpdate()` / `.executeQuery()` sink down
/// to the SQL-binding call (`createQuery` / `createNativeQuery`) and
/// synthesises a same-node `Sanitizer(SQL_QUERY)` when arg 0 is a
/// `string_literal`.
#[test]
fn fp_guard_framework_jpa_parameterised_execute() {
    let dir = fixture_path("fp_guards/framework_jpa_parameterised_execute");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, Strapi-style ORM accessor chain
/// (`<obj>.db.query(MODEL_UID).<orm_method>(...)`).  Pinned from a
/// ~98-finding `cfg-unguarded-sink` + 40-finding `taint-unsanitised-flow`
/// cluster across strapi services (api-token, transfer/token, user,
/// release, …).  When the chain shape `*.query(LITERAL).<orm_method>` ,
/// `findOne|findMany|findFirst|findUnique|find|create|createMany|update|
/// updateMany|upsert|delete|deleteMany|count|aggregate|distinct|save` ,
/// is detected, a same-node `Sanitizer(SQL_QUERY)` is synthesised that
/// reflexively dominates the sink.  Bare `connection.query(...)` and
/// chained `.then` (Promise method) are not affected.
#[test]
fn fp_guard_framework_strapi_db_query_chain() {
    let dir = fixture_path("fp_guards/framework_strapi_db_query_chain");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard: jest-style nested arrow callbacks
/// (`describe('...', () => { it('...', async () => { ... }) })`) bubble
/// inner-scope free vars (`body`, `userId`, `server.post`) up to the
/// outer arrow as synthetic Params.  Before the fix, JS/TS auto-seed
/// treated every Param whose var_name matched a handler-name (e.g.
/// `userId` via the `user*` camelCase rule) as a real formal of the
/// outer arrow and seeded it as `Source(UserInput)`, producing 934
/// phantom `taint-unsanitised-flow` findings on outline alone (the
/// dominant cluster in the JS/TS slice baseline).  Engine fix:
/// `lower_to_ssa_with_params` signals `with_params=true` to
/// `lower_to_ssa_inner`, which makes the synthetic-externals
/// classifier always exclude formals (even when the formal list is
/// empty, e.g. arrow `() => {…}`); bubbled-up free vars become
/// synthetic and the auto-seed pass skips them.  Distilled from
/// `outline/server/routes/api/comments/comments.test.ts`.
#[test]
fn fp_guard_framework_jest_test_callback_arrow() {
    let dir = fixture_path("fp_guards/framework_jest_test_callback_arrow");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, composer / PSR-4 autoloader closure includes a parameter.
/// Pinned from a 32-finding cluster in nextcloud's vendored
/// `composer/composer/ClassLoader.php` plus three further methods
/// (Router::requireRouteFile, Installer::includeAppScript,
/// Template/Base::load).  The pattern rule fires syntactically on
/// `include $var`; without taint context it over-fires when `$var` is a
/// formal parameter of the immediately enclosing function/closure with
/// no intervening reassignment.
#[test]
fn fp_guard_php_include_param_passthrough() {
    let dir = fixture_path("fp_guards/php_include_param_passthrough");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, `unserialize($x, ['allowed_classes' => …])` PHP 7+
/// structural mitigation against object injection.  Pinned from
/// nextcloud's profiler / DAV custom-properties / queue-bus call sites
/// where `allowed_classes` is set to `false`, an array literal, or a
/// class constant referring to an explicit allow-list.
#[test]
fn fp_guard_php_unserialize_allowed_classes() {
    let dir = fixture_path("fp_guards/php_unserialize_allowed_classes");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, PHP `md5()` / `sha1()` weak-hash pattern rule firing
/// syntactically on every callsite.  Real-world PHP uses these
/// functions pervasively for non-cryptographic purposes (ETag
/// generation, cache-key / array-index hashing, dedup fingerprints).
/// Layer F suppression recognises the consuming context — variable
/// LHS, member-access LHS, subscript LHS, array element key,
/// lookup-verb argument, return-from-method, hash-as-index — and
/// refuses to fire.  Distilled from nextcloud apps/dav (CalDavBackend,
/// CardDavBackend, CardDav PhotoCache), apps/contactsinteraction,
/// apps/theming (Util / CommonThemeTrait), apps/encryption KeyManager,
/// apps/files Cache, and phpmyadmin Controllers/Database / Table /
/// Display / Favorites.
#[test]
fn fp_guard_php_md5_sha1_non_crypto_use() {
    let dir = fixture_path("fp_guards/php_md5_sha1_non_crypto_use");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, JS / TS local-collection receivers.  Pinned from the
/// excalidraw element-manipulation cluster (66 → ~9 on
/// `js.auth.missing_ownership_check` over the repo).  The fix lives at
/// the deepest representable layer: SSA `TypeFacts::constructor_type`
/// recognises `new Map()` / `new Set()` / `new WeakMap()` /
/// `new WeakSet()` / `new Array()` as `TypeKind::LocalCollection`;
/// `cfg::params::ts_type_to_local_collection` extends
/// `classify_param_type_ts` so explicitly-typed params resolve to
/// `LocalCollection` independent of NestJS decorator presence;
/// `cfg::dto::collect_type_alias_local_collections` populates a
/// per-file `TYPE_ALIAS_LC` set so same-file `type X = Map<...>`
/// aliases also resolve.  The auth analyser already exempts
/// `LocalCollection`-typed receivers via
/// `auth_analysis::sink_class_for_type → InMemoryLocal`.
#[test]
fn fp_guard_auth_local_collection_receiver() {
    let dir = fixture_path("fp_guards/auth_local_collection_receiver");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, NextAuth callback definitions (`signIn`/`session`/`jwt`/
/// `authorize` etc.) are themselves the authentication boundary. Reads
/// and mutations against `user.id` / `existingUser.id` inside them
/// resolve the authenticated identity; they are not foreign-id lookups
/// driven by untrusted request input. `is_nextauth_callback_unit` in
/// `auth_analysis::checks` recognises these by name + canonical
/// callback-formal evidence (any of `user`/`token`/`account`/
/// `profile`/`credentials`/`session` in the destructured params) and
/// suppresses missing-ownership findings on every op kind.
#[test]
fn fp_guard_auth_nextauth_callback() {
    let dir = fixture_path("fp_guards/auth_nextauth_callback");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, C/C++ buffer-overflow pattern rules
/// (`c.memory.strcpy`, `strcat`, `sprintf`) over-fire when the source /
/// format-string argument is a literal whose contributed length is
/// statically bounded.  Pinned from a 938-finding cluster across postgres
/// (`pg_prewarm/autoprewarm.c::apw_start_leader_worker`,
/// `formatting.c::DCH_a_m` ternary-of-literals, `datetime.c::EncodeDateTime`
/// `%.*s`/numeric-only sprintf).  Layer D suppression in
/// `src/ast.rs::is_c_buffer_call_literal_safe`.
#[test]
fn fp_guard_c_buffer_literal_src() {
    let dir = fixture_path("fp_guards/c_buffer_literal_src");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, `cpp.memory.reinterpret_cast` over-fires on every
/// `reinterpret_cast<T>(x)` syntactically — including the canonical
/// well-defined-by-aliasing-rules targets: byte-pointer family
/// (`char*`, `uint8_t*`, `std::byte*`), `void*`, the integer
/// round-trip types `uintptr_t` / `intptr_t`, and the BSD-socket
/// address family.  These are exempt per [basic.lval]/11 and POSIX
/// socket-API contracts; suppressing them is a layer-2 structural fix
/// in `src/ast.rs::is_cpp_cast_target_type_safe`.  Genuine
/// strict-aliasing UB casts (target is a user struct / class type)
/// keep firing.  Distilled from bitcoin's leveldb / serialization /
/// IPC / netif shapes (109 → 55 findings on bitcoin in the
/// real-repo precision sweep).
#[test]
fn fp_guard_cpp_reinterpret_cast_byte_pointer() {
    let dir = fixture_path("fp_guards/cpp_reinterpret_cast_byte_pointer");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// FP guard, `rs.auth.missing_ownership_check` over-fires on Rust
/// helpers when (a) a parameter's TYPE annotation contains an
/// identifier whose lower-case form matches the framework-request-name
/// allow-list (`path`, `req`, `request`, `ctx`, `body`, …), e.g.
/// `dst: &std::path::Path` contributes the `Path` ident, or (b) a
/// receiver typed as an in-memory container (`RoaringBitmap`,
/// `HashMap<K, V>`, `HashSet<T>`) is treated as a `DbMutation` because
/// the verb-name dispatch (`is_mutation: insert/remove`) doesn't see
/// the type.  Both clusters surfaced from meilisearch's
/// `index-scheduler` crate
/// (`scheduler/process_snapshot_creation.rs::remove_tasks` for (a),
/// `scheduler/enterprise_edition/network.rs::balance_shards` for (b)).
///
/// Engine fixes:
/// * `src/auth_analysis/extract/common.rs::collect_param_names` ,
///   added a Rust `parameter` arm that descends only into the
///   `pattern` field, never the `type` field.  Type-segment idents
///   no longer pollute `unit.params` and the
///   `unit_has_user_input_evidence` gate stays closed on internal
///   helpers whose true params carry no user-input shape.
/// * `src/cfg/params.rs::rust_type_to_local_collection` (new) +
///   `classify_param_type_rust` rewire, Rust function-parameter
///   type annotations naming a known local-collection type
///   (`Vec`/`HashMap`/`HashSet`/`BTreeMap`/`BTreeSet`/`VecDeque`/
///   `BinaryHeap`/`LinkedList`/`IndexMap`/`IndexSet`/`SmallVec`/
///   `DashMap`/`DashSet`/`FxHashMap`/`FxHashSet`/`RoaringBitmap`/
///   `RoaringTreemap`, plus `[T; N]` / `[T]` array-and-slice
///   shorthand) classify the receiver as `TypeKind::LocalCollection`,
///   which `auth_analysis::sink_class_for_type` maps to
///   `SinkClass::InMemoryLocal` (non-auth-relevant).
/// * `src/ssa/type_facts.rs::is_rust_local_collection_constructor` ,
///   `RoaringBitmap` / `RoaringTreemap` added to the constructor-type
///   table so `let s = RoaringBitmap::new(); s.insert(...)` also
///   classifies correctly.
///
/// Persistent-store types like heed `Database<...>` / `sled::Db` /
/// `Mutex<HashMap<...>>` deliberately stay `None` so real IDOR
/// detection on persistent-store calls is preserved (covered by the
/// `unsafe_handler_local_collection_does_not_blanket_suppress.rs`
/// vulnerable counterpart).
#[test]
fn fp_guard_auth_rust_param_typed_local_collection() {
    let dir = fixture_path("fp_guards/auth_rust_param_typed_local_collection");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Panic guard, CFG condition-text truncation (and symex display
/// truncation) must round byte cuts down to the nearest UTF-8 char
/// boundary.  Reproduces the gogs scan crash where
/// `public/plugins/codemirror-5.17.0/mode/gherkin/gherkin.js` ships a
/// long localised regex (Gurmukhi `ਖ`, Devanagari, CJK, Cyrillic…) inside
/// a boolean sub-condition; byte 256 landed inside `'ਖ'` (3-byte UTF-8)
/// and `t[..MAX_CONDITION_TEXT_LEN].to_string()` panicked the rayon
/// worker.  Engine fix:
/// `src/utils/snippet.rs::truncate_at_char_boundary`, applied at three
/// CFG sites (`src/cfg/conditions.rs::push_condition_node`,
/// `emit_rust_match_guard_if`, `src/cfg/mod.rs::extract_condition`) and
/// two symex display sites (`src/symex/value.rs::Display`).  Invariant:
/// scanning this file must terminate without panicking, regardless of
/// where byte 256 lands inside the regex literal.
#[test]
fn fp_guard_cfg_utf8_long_condition() {
    let dir = fixture_path("fp_guards/cfg_utf8_long_condition");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
