# Changelog

All notable changes to Nyx are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For where Nyx is going, see the [Roadmap](ROADMAP.md).

## [Unreleased]

A round of cross-file FastAPI auth, two new sink/validator classes, a ~957-FP Go DAO helper precision pass, four CVE corpus pairs, and a performance pass on the auth extractor pipeline plus SCCP and the global summaries hash map.

### Added

- FastAPI cross-file `include_router` dependency tracking. New `auth_analysis/router_facts.rs` captures per-file router declarations (`<router> = X(deps=[…])`) and `<parent>.include_router(<child_module>.<child_var>)` edges in pass 1, persists them into `GlobalSummaries::router_facts_by_module`, and resolves them into the active file's `AuthorizationModel::cross_file_router_deps` at pass 2 entry. Transitive lifts (`grandparent → parent → child`) handled by iterative index walk. Module identity is the file basename without `.py` (approximate, but sufficient for airflow-style `task_instances.router` naming). Closes the airflow execution-API shape where a child router lives in `routes/task_instances.py` and its auth is declared on the parent in `routes/__init__.py`.
- FastAPI router-level `dependencies=[...]` propagation. Module-level `router = APIRouter(dependencies=[Security(...)])` declarations are pre-walked once per file, then merged onto every `@<router>.<verb>(...)` route attached in the same file. Closes airflow's execution-API routes that re-use a single `ti_id_router` declared once at module scope.
- FastAPI `Security(callable, scopes=[...])` recognised distinctly from `Depends(callable)`. Scoped Security promotes the synthetic `AuthCheck` to `AuthCheckKind::Other` (route-level scope-checked authorization), not just Login. New scope-tracking boolean threaded through `expand_decorator_calls` and `extract_fastapi_dependencies`.
- SQLAlchemy query-builder chained-call recognition. `select(X).filter_by(...)`, `query(X).filter(...)`, `select().join().where()` chains now anchor through the chain root primitive when the chain receiver type is opaque. New `db_query_builder_roots` config (Python defaults: `select`, `query`). Closes airflow `session.scalar(select(C).filter_by(conn_id=user_input))` shapes that previously dropped under the chained-call suppression in `classify_sink_class`.
- Python non-sink container constructor recognition. Bare-callee form `set()` / `dict()` / `list()` / `tuple()` / `frozenset()` / `defaultdict(...)` is now treated as a non-sink constructor, so `verified_ids = set(); verified_ids.update(myteams)` does not classify the `.update` call as `DbMutation`. Type-annotation hint form `set[int]` / `dict[str, int]` recognised via PEP 585 generic suffix strip alongside the existing angle-bracket strip. Closes the sentry `api/helpers/teams.py` shape.
- Python `request.match_info` source label (aiohttp path-parameter source).
- Receiver-side validator registry. New `labels::lookup_receiver_validator(lang, callee)` clears `Cap` from the receiver value (and call equivalents) on success, distinct from `Sanitizer` which clears caps from the return value. Python registers `relative_to → Cap::FILE_IO` so `path.relative_to(base)` (raises `ValueError` when `path` escapes `base`) drops the file-IO cap on the path. Closes the CVE-2024-23334 patched aiohttp `static_root_path.joinpath(filename).resolve().relative_to(static_root_path)` shape.
- JS/TS Array-method validator-callback narrowing. `arr.filter(isSafeIdentifier)`, `arr.find(isValidId)`, `arr.findLast(...)` with a `BooleanTrueIsValid` callback (`isValid…`, `isSafe…`, `hasValid…` and snake-case variants) propagate `validated_must` through the call's return value. Resolves callback name from both `info.arg_callees` (call-shape arguments) and SSA `value_defs[v].var_name` (bare-identifier callbacks, the dominant patched-CVE form). Strict-additive: anonymous arrows / opaque identifiers leave existing propagation untouched. `findIndex` / `every` / `some` excluded (scalar return shape). Motivated by CVE-2026-42353 (i18next-http-middleware path traversal).
- JS/TS ternary-branch source classification. `let arr = cond ? req.query.lng : "";` previously lowered each branch to a labelless Assign with empty uses, the join phi saw no taint, and downstream sinks missed the flow. `lower_ternary_branch` now runs `first_member_label` (segment-strip-and-retry classifier) on the branch AST when no `Source` label is already attached. New `cfg/cfg_tests.rs` covers the lowering shape.
- Java JPA / Hibernate Criteria API as structural SQL. New `TypeKind::JpaCriteriaQuery` for `CriteriaQuery<T>`, `CriteriaUpdate<T>`, `CriteriaDelete<T>`, `Subquery<T>`, `TypedQuery<T>`. New `cfg-unguarded-sink` SQL_QUERY suppression `sink_args_jpa_criteria_query_safe` clears the finding when any positional argument to the sink call is JpaCriteriaQuery-typed (receiver excluded; receiver of `session.createQuery(cq)` is the Session/EntityManager channel, never the SQL payload). Closes the dominant FP cluster on openmrs (169 of 216 cfg-unguarded-sink), xwiki, keycloak Hibernate DAO methods that build `cb.createQuery(Foo.class)` + Root/Predicate API queries.
- Java/Kotlin `cb.createQuery(...)`, `em.getCriteriaBuilder()`, and the JpaCriteriaQuery type chain inferred via constructor/factory return-type hints (extends the existing type-inference pipeline in `type_facts.rs`).
- PHP `fopen` modeled as `Sink(Cap::SSRF)`. Same SSRF/LFI dual-vector shape as `file_get_contents` — fires only on tainted argument. Closes CVE-2026-33486 (roadiz/documents `DownloadedFile::fromUrl` static method wrapping `fopen($url, 'r')`).
- PHP unary-op-expression negation recognition. tree-sitter-php emits `unary_op_expression` for unary `!` (and `-`/`+`/`~`); CFG `detect_negation` and condition-chain decomposition now match it. Without this, `if (!validate($x))` carried `condition_negated=false` and the True branch was treated as the validated path even though it is the rejection path. New PHP fixture `safe_camelcase_validator_negated.php` pins the lowering.
- PHP `Serializable::unserialize($input)` magic-method passthrough recognition. The legacy `Serializable` interface contract (deprecated since PHP 8.1) requires the implementation to call `\unserialize($input)` on the formal parameter inside `public function unserialize($x) { ... }`. PHP itself invokes the method when restoring an instance, so the body's call cannot be removed without breaking the interface. `php.deser.unserialize` now suppresses inside this exact shape (method named `unserialize`, single formal, bare-parameter argument). Class-level `Serializable` implementation is the actionable signal (fix is migration to `__serialize` / `__unserialize`). Closes joomla / drupal Serializable-implementing class FPs.
- PHP container kinds: `declaration_list`, `interface_declaration`, `trait_declaration`, `enum_declaration`, `enum_declaration_list` mapped to `Kind::Block` so methods inside them participate in CFG construction.
- Go DAO-helper id-scalar precision pass. For non-route Go units, a parameter whose declared type is a bounded primitive scalar (`int64`, `uint32`, `string`, `bool`, `byte`, `rune`, `float64`, …) and whose name is id-shaped (`id`, `*Id`, `*_id`, `*ids`) is dropped from `unit.params` before ownership-check evaluation. Real Go HTTP handlers always carry a framework-request-typed param (`*http.Request`, `*gin.Context`, `echo.Context`, `*fiber.Ctx`); per-framework route extractors set `include_id_like_typed=true` so id-shaped path params survive on real routes. Mirrors the existing Python `is_python_id_like_typed_param` filter. Closes ~957 `go.auth.missing_ownership_check` findings on gitea backend DAO helpers (`func GetRunByRepoAndID(ctx, repoID, runID int64)`, `func DeleteRunner(ctx, id int64)`, the entire `models/...` layer where the ownership check sits in the calling route handler) and equivalent shapes in minio / Go ORM codebases.
- Bare-callee verb-name fallback gate. `list(...)`, `filter(...)`, `update(...)`, `create_audit_entry(...)`, `update_coding_agent_state(...)` (no receiver dot at all) no longer classify as `DbMutation` / `DbCrossTenantRead` via the loose verb-name fallback. Real ORM/DB calls always carry a receiver (`User.find(id)`, `Model.objects.filter`, `repo.save(x)`); a bare `list(events)` is the Python builtin and `filter(fn, xs)` is `Iterable.filter`. The realtime / outbound / cache prefix dispatches still match by chain root. New helper `receiver_is_simple_chain(callee)` requires a non-chained receiver dot.
- Go variadic `parameter_declaration` named-field handling for `collect_param_names`. `name` and `type` named fields read directly so type-segment identifiers no longer pollute the param-name set (`info *PackageInfo` no longer contributes `PackageInfo`).
- Phase 1 caller-scope IPA: same-file route-handler-to-helper auth lift. New `apply_caller_scope_propagation` walks every non-route helper unit; if its in-file callers are non-empty AND every caller is itself an authorized route handler (route-level non-Login auth check) or already authorized via this same propagation, the caller's checks lift onto the helper as synthetic `is_route_level=true` `AuthCheck`s. Iterated to a small fixpoint so transitive helper chains (`route → mid_helper → leaf_helper`) are covered. Refuses to authorize helpers with no in-file caller, helpers called from a mix of authorized and unauthorized callers, and helpers called only from un-lifted helpers. Cross-file equivalent deferred (see `deep_engine_fixes.md`). Closes the dominant FastAPI / Django / Flask "route authenticates via decorator/dependency, then delegates to a private helper that performs the sink" FP shape on sentry / saleor / airflow.
- New Python pattern `py.xss.make_response_format` (Tier B). Flask `make_response(<f-string-or-concat>)` reflection. Recognises both bare `make_response(...)` and `flask.make_response(...)`. Closes CVE-2023-6568 (mlflow auth `create_user` reflected the attacker-controlled `Content-Type` header into the response body via `make_response(f"Invalid content type: '{content_type}'", 400)`).
- C CVE corpus extended. CVE-2017-1000117 (git argv injection via `ssh://-oProxyCommand=…`) vulnerable + patched fixtures under `tests/benchmark/cve_corpus/c/CVE-2017-1000117/`. Three-layer engine gap deferred (array-element taint propagation, `c.cmdi.exec*` AST patterns, dash-prefix-byte sanitizer recognition).
- Python CVE corpus extended. CVE-2023-6568 (mlflow XSS), CVE-2024-21513 (langchain SQL/JINJA), CVE-2024-23334 (aiohttp static-file path traversal) vulnerable + patched fixtures.
- PHP CVE corpus extended. CVE-2026-33486 (roadiz/documents SSRF) vulnerable + patched fixtures.
- JavaScript CVE corpus extended. CVE-2026-42353 (i18next-http-middleware path traversal) vulnerable + patched fixtures.
- Cross-file FastAPI integration test `tests/fastapi_cross_file_include_router_tests.rs` with airflow-shaped fixture tree under `tests/fixtures/auth_cross_file/airflow_execution_api_includes/`.
- Per-language safe / vuln Python auth fixtures: `safe_local_set_update_no_orm.py`, `vuln_local_set_with_user_id_query.py`, `vuln_fastapi_route_no_dependencies_sqla.py`, `vuln_fastapi_route_security_no_scopes.py`, `safe_fastapi_route_security_scopes.py`, `vuln_fastapi_router_no_dependencies.py`, `safe_fastapi_router_level_security_scopes.py`, `safe_bare_callee_no_receiver.py`, `vuln_caller_scope_helper_under_bare_route.py`, `safe_caller_scope_helper_under_authorized_route.py`, `safe_relative_to_validator.py`, `path_traversal_no_relative_to.py`. Java `SafeJpaCriteriaQuery.java`. Go `safe_dao_helper_id_scalar.go`, `vuln_repo_findbyid_no_auth.go`. PHP `ssrf_class_method_fopen.php`, `safe_camelcase_validator_negated.php`, `safe_serializable_magic_method_unserialize.php`, `vuln_serialize_method_named_unserialize_with_user_input.php`. JS `path_traversal_ternary_source.js`, `safe_ternary_const_branches.js`. TS `safe_session_user_id_copy.ts`, `vuln_target_user_id_no_check.ts`.

### Performance

- Hoisted `collect_top_level_units` out of the per-extractor loop in `extract_authorization_model`. Multi-extractor languages (Go gin+echo, JS/TS express+koa+fastify, Python flask+django, Rust axum+actix_web+rocket, Ruby sinatra) re-walked the entire AST and rebuilt the `Function`-kind unit set per extractor (then deduped by span). New `AuthExtractor::requires_top_level_units()` opt-out for Spring / Rails which build their own. Was 46% of `extract_authorization_model` wall-clock on the mattermost/server/channels/app subtree.
- Single `AuthorizationModel` build per file in fused mode. Pre-fix the diag path and the per-file summary path each ran their own `extract_authorization_model`, duplicating the hoisted unit pass + every framework extractor's AST walk. Auth summaries extracted from the base model (pre var-types, pre-helper-lifting) so the persisted per-file summary matches the legacy `extract_auth_summaries_by_key` path bit-for-bit.
- O(N) shallow value-ref emission in `collect_unit_state`. Previous per-node `extract_value_refs(node, bytes)` walked the entire subtree on every recursion level (O(N²) per body); the recursion below already visits every descendant once. New `append_shallow_value_ref` emits the node's own ref and lets recursion handle the descent. Public callers of `extract_value_refs` (`collect_call`, `collect_condition`, assignment-side extraction) keep the deep walk. Was ~17%+15%+11% of wall-clock split across `build_function_unit_with_meta`, `collect_unit_state`, and `extract_value_refs` on mattermost/server/channels/app.
- Per-`ParsedFile` `body_const_facts_cache: OnceCell`. SSA + const-prop + type-fact build was running 2-3× per body across `run_cfg_analyses_with_lowered`, `run_auth_analyses`, and `collect_file_var_types`. Single-pass cache; gin profile dropped from 13.6% to ~4.5%.
- Sparse Conditional Constant Propagation switched from `HashMap<SsaValue, _>` and `HashSet<(BlockId, BlockId)>` to dense `Vec` per-value lattice and per-destination predecessor `SmallVec<[BlockId; 2]>`. The inner SCCP fixed-point loop no longer SipHashes a 64-bit pair for every operand of every phi. Public `ConstPropResult` shape unchanged (one final O(num_values) HashMap conversion).
- `GlobalSummaries.by_key` switched from stdlib SipHash `HashMap` to `FxHashMap` (rustc-hash 2.1). `FuncKey` carries 3 String fields, so any HashMap operation hashes ≥30 bytes; FxHash is ~5× faster on this workload. Seed is fixed (no DoS hardening), fine for an in-process index keyed by program-derived names.
- `large_go_module.go` perf fixture (1493 lines) added to `benches/perf_fixtures/`; `benches/scan_bench.rs` extended with auth-extractor, SCCP, and summary-resolution rows.

### Fixed (false positives)

- ~957 gitea backend DAO `go.auth.missing_ownership_check` findings (id-scalar precision pass, see Added).
- 169 of 216 openmrs `cfg-unguarded-sink` findings (JpaCriteriaQuery type, see Added). Equivalent reductions on xwiki / keycloak Hibernate DAO clusters.
- joomla and drupal `php.deser.unserialize` flagged inside `Serializable::unserialize($input)` magic-method bodies (passthrough recognition, see Added).
- airflow execution-API routes flagged `missing_ownership_check` despite being authorized via cross-file `include_router` chains and module-level `APIRouter(dependencies=[…])` declarations (router_facts + router-level dep propagation, see Added).
- sentry `verified_ids = set(); verified_ids.update(myteams)` flagged as `DbMutation` (Python container constructor recognition, see Added).
- aiohttp `path.relative_to(static_root_path)` rejected as a path-traversal validator (receiver-side validator registry, see Added).
- i18next-http-middleware `arr.filter(utils.isSafeIdentifier)` not narrowing taint on the result (Array-method validator-callback narrowing, see Added).
- `cond ? req.query.lng : ""` ternary lost `Source` label on the truthy branch (ternary-branch source classification, see Added).
- `if (!validate($x))` rejection-arm narrowing flipped on PHP unary `!` (unary_op_expression recognition, see Added).
- mlflow `make_response(f"Invalid content type: '{content_type}'")` (Tier B pattern, see Added).
- Bare-callee verb-name dispatch on Python builtins / locally-defined helpers (`list`, `filter`, `update`, `create_audit_entry`, `update_coding_agent_state`, see Added).
- FastAPI `Depends(...)` / `Security(...)` deps declared on a module-level `APIRouter` no longer dropped on every attached route.
- FastAPI `Security(callable, scopes=[...])` no longer downgraded to a Login-only check.

### Other

- New `cfg/cfg_tests.rs` covers ternary-branch CFG lowering shapes.
- New `summary/tests.rs` covers cross-file `include_router` summary persistence and resolution.
- Refactor passes across `auth_analysis`, `ssa/const_prop`, `ssa/type_facts`, `summary`, and the per-framework auth extractors (cleaner conditional checks, simpler function signatures, deduplicated assertions). No behaviour change.

## [0.6.1] - 2026-05-03

A precision pass on auth and resource analysis plus three fresh CVE corpus pairs, plus a UTF-8 slice panic in the path abstract domain. Closes ~1900 Go auth FPs on gitea-shaped helpers, the mastodon/diaspora private-callback Ruby controller pattern, and a phantom-taint outbreak from JS/TS / Java lambda shorthand in jest-style nested test callbacks.

### Added

- Java JDBC raw-SQL sinks. `Statement.execute`, `Statement.executeBatch`, and `Statement.executeLargeUpdate` modeled as `SQL_QUERY` sinks, classified via type-qualified resolution (`DatabaseConnection.execute`) so bare `execute` (Runnable, Executor, HttpClient) does not over-fire. `conn.createStatement()` and `conn.prepareCall()` now infer return type `DatabaseConnection`, so the JDBC chain `Statement s = conn.createStatement(); s.execute(q)` types `s` correctly. Closes GHSA-h8cj-hpmg-636v (Appsmith FilterDataServiceCE.dropTable). Vulnerable + patched Java fixtures added.
- Java/Kotlin `Pattern.matcher(value).matches()` chain recognised as a `ValidationCall` allowlist. Receiver of `.matcher(` must contain `regex` or `pattern`. Validation target is the `.matcher()` argument, not the bare `.matches()` receiver. Branch narrowing applies the `validated_must` to the input variable on the surviving branch. Same GHSA as above (`FILTER_TEMP_TABLE_NAME_PATTERN.matcher(tableName).matches()`).
- Per-parameter SSA summary probe now receives `BodyMeta.param_types`, so `extract_ssa_func_summary` runs a local `analyze_types_with_param_types` pass before extraction. Helper bodies whose sinks resolve only via type-qualified callees (e.g. `DatabaseConnection.execute` for JDBC `Statement.execute`) no longer drop the sink during cross-function summary extraction. Fixes the Appsmith helper `executeDbQuery(query)` that routed SQL through `statement.execute(query)`.
- Short-circuit branch condition CFG nodes now mirror `condition_vars` into `taint.uses`, so `apply_branch_predicates` interns the variable for short-circuit-decomposed validators (`if (x == null || !regex.matcher(x).matches()) throw`). Without this, the per-disjunct cond nodes built via `build_condition_chain` silently no-opped and `x` never reached `validated_must` on the surviving branch.
- Go `goqu.L(s)` and `goqu.Lit(s)` raw-SQL literal builders modeled as `SQL_QUERY` sinks. Safe siblings (`goqu.I` identifier, `goqu.C` column, `goqu.T` table, `goqu.V` parameterised value, `goqu.SUM`, `goqu.COUNT`, …) stay unlabeled. Gin source list extended with the array-returning siblings of the existing scalar helpers: `c.QueryArray`, `c.GetQueryArray`, `c.PostFormArray`, `c.GetPostFormArray`. Closes CVE-2026-41422 (daptin: `c.QueryArray("column")` → `goqu.L(project)` with the loop variable lifted through `for _, project := range columns`). Vulnerable + patched Go corpus pair under `tests/benchmark/cve_corpus/go/CVE-2026-41422/`.
- Go `for ident := range iter` def-use lifting. The `range_clause` child of `for_statement` is now consulted when `left`/`right` aren't direct fields of the `for` node, so taint from the iterable reaches the loop binding. Required for the daptin CVE shape above.
- Rust format-string named-argument lifting (`format!("...{x}...")`, stable since 1.58). Identifiers captured by `{name}` / `{name:fmt-spec}` are pulled into the call's `uses` for known format-style macros: `format`, `print`/`println`, `eprint`/`eprintln`, `write`/`writeln`, `panic`, `format_args`, `assert`/`debug_assert`, `todo`, `unimplemented`, `unreachable`, plus log-crate severity macros (`info`, `warn`, `error`, `debug`, `trace`). Recursive descent through one or two layers of expression wrapping (`format!("{x}").to_owned()`, RHS chained method calls). Without this, taint stopped at the macro boundary. `let q = format!("...{x}...")` carried no `x` because the identifier lives in format-string bytes rather than as a separate AST argument node. Mirrors the Python f-string lifter.
- Rust CVE corpus extended. CVE-2023-42456, CVE-2024-32884, CVE-2025-53549 vulnerable + patched fixtures under `tests/benchmark/cve_corpus/rust/`.
- Java lambda shorthand recognised by `extract_param_meta`. `lambda_expression`'s `parameters` field as a bare `identifier` (`cmd -> …`) or as an `inferred_parameters` wrapper around identifiers (`(a, b) -> …`) was not matching the formal_parameter / spread_parameter kinds in `PARAM_CONFIG`, so the lambda appeared parameterless and the SSA pipeline treated its formals as closure captures. Mirrors the JS/TS arrow shorthand path.

### Fixed

- Panic on non-ASCII input to `has_first_char_absolute_check` in the path abstract domain. The 32-byte search window around `[0]` was sliced as `&clause[lo..hi]` (str), which panicked when `hi` landed inside a multi-byte UTF-8 char (e.g. the em dash `—`, bytes 34..37). Switched to `&bytes[lo..hi]` with `windows()` byte-pattern checks; all needles are ASCII so the searches are equivalent. Surfaced by `cargo fuzz` (`scan_bytes` target, `.c` extension path, embedded `—` in a comment near `s[0] == '/'`). Regression test added.

### Fixed (false positives)

- Go `unit_has_user_input_evidence` framework-request-name allow-list narrowed for Go. `ctx`, `context`, `info`, `body`, `path`, `payload`, `dto`, `form`, `query` are no longer treated as user-input indicators on Go: in Go these are `context.Context` (cancellation/value-bag from the stdlib) or struct-pointer payload params (`info *PackageInfo`, `opts *FooOptions`), not request bindings. Go HTTP frameworks bind the request to per-framework typed params (`r *http.Request`, `c *gin.Context`, `c echo.Context`, `c *fiber.Ctx`); these arrive at the gate via `RouteHandler` kind or the type-aware param filter below. Stdlib `req` / `request` (the `*http.Request` convention) preserved. Other languages keep the broader allow-list.
- Go param collection drops `ctx context.Context` and `ctx context.CancelFunc` parameters entirely rather than seeding their names into `unit.params`. Tree-sitter-go's `parameter_declaration` exposes `name` and `type` as named fields; descend only into `name` so type-segment identifiers don't pollute the param-name set (`info *PackageInfo` no longer contributes `PackageInfo`). Together with the allow-list narrowing above, closes ~1900 `go.auth.missing_ownership_check` findings on gitea backend helpers whose only "user-input evidence" was the ubiquitous `ctx context.Context` first param.
- Ruby controller method visibility + filter-callback gate. Methods marked `private` (bare `private` directive, targeted `private :foo, :bar`, or `protected`) and Rails filter callback targets (`before_action`, `after_action`, `around_action`, their `prepend_*` / `append_*` / `skip_*` siblings, and the legacy `*_filter` aliases) are no longer emitted as `Function` units. Visibility tracking is class-body source-order with two directive forms (bare toggles default visibility, targeted explicitly marks named methods). Block-form filters (`before_action do … end`) carry no symbol arg and are correctly ignored. Closes mastodon / diaspora `rb.auth.missing_ownership_check` flood on `set_X` row-fetch helpers used as `before_action` callbacks.
- Field-LHS resource acquires no longer counted as local resource leaks at the `apply_assignment` site. `e->name = (char *)e + sizeof(*e)` (sub-buffer alias inside a returned struct) and `mem->buf = ptr` (local-into-field ownership transfer) now mark the RHS local `MOVED` and stop tracking the field as a separately OPEN resource. The parent struct owns the field's lifecycle. Cross-language (distinct from the Go-only `apply_call` field-LHS gate, which is restricted because JS/TS class-field acquires `this.fd = fs.openSync(...)` are the documented expected leak pattern in that path). Closes curl `entry_new` and equivalent C/C++ shapes in openssl / postgres.
- Empty-formals SSA lowering signal. `lower_to_ssa_with_params` now sets `with_params=true` even when `formal_params` is empty, so an arrow `() => {…}` is treated as "explicitly zero formals" rather than "no formals info". External vars in a zero-formal arrow are now correctly tagged as synthetic closure captures, so the JS/TS / Java auto-seed pass cannot mistake a bubbled-up free var (e.g. `userId` lifted from a nested jest test callback) for a real handler formal. Closes 934 phantom taint findings on the outline test suite (`describe("…", () => { test("…", () => { server.post(…) }) })`-shaped fixtures).
- Rust integer-typed values now suppress `Cap::FILE_IO` at the abstract-domain leaf gate (previously HTML_ESCAPE only). An integer's decimal representation is digits with optional leading `-`, never path metacharacters (`/`, `\`, `.`); magnitude is irrelevant. Closes the sudo-rs RUSTSEC-2023-0069 patched FP `let uid: u32 = user.parse()?; path.push(uid.to_string())`.

## [0.6.0] - 2026-05-02

A focused release that splits data-exfiltration off from SSRF and ships sinks for outbound HTTP request bodies across all 10 languages, with calibration tuned so plain user input echoed back upstream does not fire.

### Added

- New `taint-data-exfiltration` rule, separate from SSRF. Fires when a Sensitive-tier source (cookie, header, env, file, database, caught exception) reaches the body, headers, or json payload of an outbound HTTP call. Plain user input gets suppressed at emission time so a gateway echoing `req.body` back upstream is not flagged.
- Sinks ship for `fetch` body, `XMLHttpRequest.send`, Python `requests.post` and `httpx.AsyncClient.post`, Java JDK `HttpClient.send` with `BodyPublishers`, OkHttp builder chains, Apache HttpClient `execute`, RestTemplate, WebClient, Go `http.Post` and `http.NewRequest` + `Do`, Rust `reqwest`/`ureq`/`surf`/`hyper` body/json/form/multipart chains, Ruby `Net::HTTP.post` and RestClient, C and C++ `curl_easy_setopt(CURLOPT_POSTFIELDS, ...)` gated by the macro arg.
- Three suppression knobs:
  - Sanitizer convention. `logEvent`, `forwardPayload`, `tracker.send`, `analytics.track`, `metrics.report`, `serializeForUpstream` are treated as `Sanitizer(data_exfil)` by default. Add your own with the standard custom-rule path.
  - Trusted destination allowlist in `detectors.data_exfil.trusted_destinations`. Matched against the abstract-string domain prefix; a literal or template prefix that begins with one of these entries drops the cap.
  - Detector toggle `detectors.data_exfil.enabled = false` strips the cap before emission. Other taint classes are unaffected.
- Calibration. Severity is High for cookie or env sources, Medium for header, file, database, or caught-exception sources. Confidence stays at Medium even with strong corroboration, drops to Low without abstract or symbolic backing, and drops one tier on path-validated flows. SARIF output carries a `properties.data_exfil_field` entry on data-exfil findings, set to the destination object-literal field the leak reached (`body`, `headers`, or `json`).
- Benchmark coverage. 13 vulnerable fixtures across 8 languages under `tests/benchmark/corpus/{lang}/data_exfil/` and 6 paired safe fixtures for the sensitivity gate and sanitizer convention. New `data_exfil` row in the per-class breakdown. Per-class CI floor at P, R, F1 ≥ 0.85 (current baseline is 1.000).
- Backwards taint walk recognises `Cap::DATA_EXFIL` and emits the same rule ID.
- Ruby SSRF coverage. `OpenURI.open_uri` now classified as an SSRF sink (the low-level fetcher that `URI.open` delegates to). Closes the CarrierWave CVE-2021-21288 download path and equivalent gem shapes that route through `OpenURI` directly.
- Ruby chained-call wrapper classification. Statement-level wrappers like `YAML.safe_load(File.read(filename))` and `Marshal.load(File.read(p))` now classify the inner sink for cross-function summary extraction. Without this, the outer call became a non-sink node and the inner sink was lost when the helper was summarised.
- Ruby CVE corpus. Vulnerable + patched fixtures added for CVE-2021-21288 (CarrierWave SSRF) and CVE-2023-38337 (rswag path traversal).
- Lodash `_.template` modeled as a gated `Cap::CODE_EXEC` sink. Activates on the template-string argument; suppresses when arg-1 carries a literal `{ evaluate: false }`. Closes Strapi CVE-2023-22621 (server-side template injection → RCE via `<% … %>` evaluate blocks). Vulnerable + patched fixtures added under `tests/benchmark/cve_corpus/javascript/CVE-2023-22621/`.
- JS/TS gated-sink kwarg extractor falls back to inspecting arg-1 object literals (`fn(x, { evaluate: false })`) when the language has no `keyword_argument` node. Required so the lodash gate can read its options object.
- Lodash double-call form (`_.template(t)(data)`) routes through `find_chained_inner_call` so the outer call's gated-sink rebinding fires.
- Cross-function helper-validation propagation. New `SsaFuncSummary.validated_params_to_return` field records parameter indices whose taint flow to the return value is fully validated by a dominating predicate (regex allowlist, type check, validation call) on every return path. At call sites, each tainted argument passed to a validated position — and the call's own return value — are marked `validated_must` / `validated_may` in the caller's SSA taint state, the same way an inline `if (!regex.test(x)) throw` would. Closes the helper-validator gap behind PayloadCMS CVE-2026-25544 (Drizzle SQL injection in `sanitizeValue`). Vulnerable + patched TypeScript fixtures added.
- Destructured-arg sibling expansion in per-parameter taint summary probing. JS/TS object-pattern formals (`({ column, operator, value }) => …`) now seed every binding sharing the slot, and any sibling reaching `validated_must` counts as the slot being validated. New `BodyMeta.param_destructured_fields` carries sibling lists alongside `params` and `param_types`. JS `PARAM_CONFIG` accepts `assignment_pattern` (default-value formals) and `object_pattern` (destructured formals).
- Regex-allowlist branch narrowing. `<X>.test(value)` / `<X>.match(value)` / `<X>.matches(value)` where the receiver name contains `regex` or `pattern` classifies as a `ValidationCall` and narrows the call's first argument, not the regex receiver. Was also extended to `extract_validation_target` so the surviving branch validates `value`, not the regex object. Motivated by Payload CVE-2026-25544 (`if (!SAFE_STRING_REGEX.test(value)) throw …`).
- TypeScript template-substring (`${fn(arg)}`) call-resolution arity-hint fallback. When CFG lowering drops `arg_uses` but `args` is non-empty, the resolver passes `None` so the unique-name fallback can still pick up the lone candidate.
- Caller-scope-entity exemption in `rs.auth.missing_ownership_check`. `<entity>.id` / `<entity>.pk` no longer fires when `<entity>` is a unit parameter named after a multi-tenant scope primitive: `organization` / `org`, `project`, `team`, `workspace`, `tenant`, `account`, `community`, `group`, `repository` / `repo`, `company`. Other field names (`.name`, `.slug`) still flag, and `user` / `member` / `actor` are deliberately excluded (handled by `is_actor_context_subject`). Closes a flood of FPs in Sentry / Saleor / Discourse / Mastodon-shaped multi-tenant helpers (`get_environments(request, organization)`, `_filter_releases_by_query(qs, organization, …)`).
- Auth value-ref walker recurses into the `value` child of `keyword_argument` / `keyword_arg` / `named_argument` nodes. `Model.objects.filter(organization_id=org.id)` no longer surfaces the kwarg key (`organization_id`) as a bare-identifier user-input subject — the schema column name is fixed at call time.
- Test-decorator denylist for Flask route extraction. `mock.patch`, `mock.patch.object` / `.dict` / `.multiple`, `unittest.mock.*`, `monkeypatch.setattr` / `setenv` / `delattr` / `delenv`, and `pytest.mark.parametrize` no longer collide with `<app>.patch` route registration. Stops every `@mock.patch("…")`-decorated test method from being attached as a Flask PATCH handler and flagged as `missing_ownership_check`.
- Typed-extractor route-level guard injection for axum and actix-web. Handlers registered via attribute macros (`#[get("/path")]`, `#[routes::path(…)]`) or via external service-config builders previously never had their typed-extractor guards seeded. New `apply_typed_extractor_guards_to_units` walks every `Function`-kind unit and injects guard checks from typed-extractor params, complementing the route-walk path that already covered `.route(...)` registration.
- New auth config key `policy_guard_names`. Typed-extractor wrappers that prove route-level capability/policy enforcement (e.g. meilisearch's `GuardedData<ActionPolicy<X>, _>`) are recognised distinctly from authentication-only wrappers. Matched as last-segment + case-insensitive `starts_with`. Rust default: `["Guarded"]`. Distinct from `login_guard_names` so the pattern doesn't pollute regular call recognition (a function like `guarded_load(..)` is not a login guard).
- Outer-wrapper-aware classification of typed extractors. `GuardedData<ActionPolicy<X>, Data<AuthController>>` is classified by the outer `GuardedData` (policy-bearing → `AuthCheckKind::Other`), not by whether an inner generic arg substring-matches `auth`. Bare data-only extractors (`Path<u64>`, `Query<X>`, `Json<X>`, `Form<X>`, `State<X>`, `Extension<X>`, `Data<X>`) outer-name-match early-return to `None` regardless of inner type tokens. Reference-marker (`&`, `&mut`, `&'a`) and module-path (`std::collections::`) prefixes stripped before matching.
- Project-level web-framework signal in Rust auth analysis. New `FrameworkContext::lang_has_web_framework(lang)` is three-valued: `Some(true)` when manifest names a framework, `Some(false)` when the manifest was inspected and named none, `None` when no manifest was inspected. New `rust_file_imports_web_framework` does a per-file `axum::` / `actix_web::` / `rocket::` / `axum_extra::` import probe (8 KB head). When the project's Cargo.toml is inspected and lists no Rust web framework AND the file does not directly import one, the `context_inputs` and param-name-heuristic arms of `unit_has_user_input_evidence` are suppressed. `RouteHandler` classification (concrete route-registration evidence) still bypasses the gate. Closes a flood of `missing_ownership_check` FPs in non-web Rust crates — e.g. zed-style desktop / GUI codebases where a debug-session handle named `session` would trip `matches_session_context` on `session.update(cx, …)`. Currently Rust-only; other languages keep prior behavior (`None`).
- Rust auth corpus extended with `safe_actix_guarded_data_extractor.rs` and `unsafe_actix_no_guarded_data_extractor.rs` (typed-extractor guard injection); `safe_non_web_rust_project/` and `unsafe_actix_web_project_no_check/` (full Cargo.toml + src/lib.rs project shapes for the framework-signal gate).
- Python auth corpus extended with `vuln_user_id_param_no_auth.py`, `safe_django_orm_caller_scoped_entity.py` (caller-scope-entity exemption), `safe_mock_patch_test_method.py` (test-decorator denylist).
- Go safe corpus extended with `safe_inner_call_close_in_arg.go` (`require.NoError(t, f.Close())` shape), `safe_struct_field_resource_owned_by_struct.go` (field-LHS ownership transfer), and a `vuln_resource_leak_no_close.go` regression guard.

### Fixed (false positives)

- C++ `cpp.memory.reinterpret_cast` no longer fires when the target type is well-defined by C++ aliasing rules. Suppressed targets: byte-pointer family (`char*`, `unsigned char*`, `signed char*`, `wchar_t*`, `uint8_t*`, `int8_t*`, `std::byte*`, `byte*`), `void*`, integer round-trip (`uintptr_t`, `intptr_t`, and `std::` variants, no pointer required), and the BSD socket address family (`sockaddr*`, `struct sockaddr*`, `sockaddr_in*`, `sockaddr_in6*`, `sockaddr_un*`, `sockaddr_storage*`). User-defined struct or class pointer targets keep firing. Closes ~70% over-fire on serialization, hashing, IPC, and socket-API code where the cast is the standard-blessed idiom.
- PHP `php.crypto.md5` and `php.crypto.sha1` suppress when the call's consuming context yields a non-cryptographic identifier name. Recognised contexts: assignment LHS (variable, `$obj->property`, `$arr['key']`), array element keys, subscript indices, return statements (resolved to enclosing method or function name with `get` prefix stripped), and method-call arguments where the method is a key/cache/lookup verb (`get`, `set`, `has`, `delete`, `fetch`, `store`, `find`, `getItem`, `setItem`). Names containing a crypto keyword (`password`, `secret`, `token`, `signature`, `hmac`, `digest`, `salt`, `key`) keep firing. Closes ETag generation, cache-key hashing, dedup fingerprint, and `getCacheKey()`-style false positives in real PHP repos (phpmyadmin, nextcloud).
- JS and TS `secrets.fallback_secret` no longer fire on empty-string fallbacks (`process.env.X || ""`). Developers write `|| ""` to satisfy non-undefined string types without committing a real secret. Non-empty literal fallbacks still fire.
- Path-traversal sink suppression accepts canonicalised-and-rooted shapes. New `PathFact::is_path_traversal_safe` predicate clears `Cap::FILE_IO` when the path is dotdot-free and either non-absolute or carries a verified prefix-lock. New `OPAQUE_PREFIX_LOCK` marker records the structural invariant ("rooted under SOME prefix") when the `starts_with`-style guard's argument is a method call, field access, or configured root rather than a string literal. Closes the Ruby `File.expand_path + start_with?(root)` shape (rswag CVE-2023-38337 patched counterpart), the Python `os.path.realpath + .startswith(root)` shape, and the JS `path.resolve + .startsWith(root)` shape. `classify_path_assertion` extended to JS `.startsWith(...)`, Python `.startswith(...)`, Ruby `.start_with?(...)` (paren and paren-less), and Go `strings.HasPrefix(...)`.
- Branch narrowing now flips prefix-lock attachment under condition negation. For `if !target.startsWith(ROOT) { return; }` the lock attaches to the surviving block, not the rejection arm. Rejection-axis narrowing is unchanged because the rejection classifier is text-level and already accounts for leading `!`.
- Go field-LHS resource acquires no longer counted as local resource leaks. `b.cpuprof = os.Create(...)` transfers ownership to the containing struct; closure responsibility belongs to a paired `Stop()` / `Release()` method on the struct's lifecycle. Gated in both `state/transfer.rs::apply_call` and `cfg_analysis/resources.rs::run`. Restricted to Go (`Lang::Go` check) — JS/TS class-field acquires (`this.fd = fs.openSync(...)`) keep being tracked because the leak fixtures rely on it. Production trigger: prometheus `cmd/promtool/tsdb.go::startProfiling` cluster (`b.cpuprof`, `b.memprof`, `b.blockprof`, `b.mtxprof`).
- Go inner-call release in argument position. `require.NoError(t, f.Close())`, `errs = append(errs, f.Close())`, JUnit `assertEquals(0, in.read())` — releases that live in argument position now mark the receiver `CLOSED`. Bare-receiver inner calls only (chained-receiver releases stay owned by `chain_proxies`); marks `CLOSED` only with no `DoubleClose` attribution; respects `in_defer` for symmetry.

### Other

- Action download script warning for the mutable `latest` tag now references `v0.6.0` instead of `v0.5.0`.

## [0.5.0] - 2026-04-29

The biggest release since launch. The taint engine was rebuilt on top of an SSA IR, cross-file analysis was deepened across the board, and Nyx now ships a local web UI for triaging findings without leaving your machine.

> Heads-up: false positives or regressions on cross-file flows are possible. Please open an issue with a minimal reproduction if you hit one.

### Highlights

- **New SSA-based taint engine.** Block-level worklist analysis over a pruned SSA IR, replacing the legacy BFS engine across all 10 languages. More precise, easier to extend, and the foundation for everything else in this release.
- **Cross-file analysis.** Function summaries (including the new SSA summaries) flow across files via SQLite-backed persistence. Callee bodies can be inlined for context-sensitive analysis (k=1) and walked symbolically across file boundaries.
- **Symbolic execution layer.** Candidate findings are walked symbolically from source to sink, producing concrete attack witnesses, pruning infeasible paths, and (optionally) handing constraints off to Z3.
- **Local web UI (`nyx serve`).** React + Vite frontend for browsing findings, viewing flow paths, and triaging results. Triage decisions persist to `.nyx/triage.json` so they version with your code.
- **Hostile-repo hardening.** Path containment, loopback-only serving, CSRF tokens, bounded artifact reads. Safe to run on untrusted code.
- **Tighter false-positive controls.** Type-aware sink suppression, abstract interpretation (intervals + string prefixes), constraint solving, allowlist and type-check guard recognition, and confidence scoring on every finding.

### Engine

- SSA IR with dominance-frontier phi insertion. The optimization pipeline runs constant propagation, branch pruning, copy propagation, alias analysis, DCE, type facts, and points-to in sequence.
- Multi-label classification. A single API can carry both Source and Sink labels (e.g. PHP `file_get_contents`, Java `readObject`).
- Gated sinks. `setAttribute`, `parseFromString`, etc. only activate when the constant attribute argument is dangerous, and only the payload argument is treated as taint-bearing.
- Container taint with per-index precision and bounded points-to. Aliased containers share heap identity correctly.
- Loop-aware analysis: induction-variable pruning, widening at loop heads, bounded unrolling in symex.
- Path-sensitive phi evaluation propagates validation when all tainted predecessors are guarded.
- Per-return-path summaries decompose function effects when paths produce different taint behavior.
- Cross-file SCC fixed-point. Mutually recursive functions across files now reach a joint convergence.
- Demand-driven backwards analysis (off by default) annotates findings with cutoff diagnostics.
- Direction-aware engine notes (`UnderReport`, `OverReport`, `Bail`) flow into confidence scoring, ranking, and the new `--require-converged` strict mode.
- Synthetic field-write inheritance: `u.Path = "/foo"` no longer drops taint carried by other fields of `u`. Fixes Owncast CVE-2023-3188 (SSRF).
- Phantom-Param-aware field suppression skips method/function references that share a base name with a tainted variable.
- Validation err-check narrowing for the two-statement Go idiom `_, err := strconv.Atoi(input); if err != nil { return }` — `input` is marked validated on the surviving `err == nil` branch.
- Go: `strings.Replace` / `strings.ReplaceAll` recognised as a sanitizer when the OLD literal contains a known-dangerous payload (shell metachars, path-traversal, HTML, SQL) and the NEW literal does not reintroduce one.
- Go: literal-strip cap detection extended to shell metachars (`;`, `|`, `&`, `$`, backtick) and SQL metachars (`'`, `"`, `--`).
- Go: `interpreted_string_literal` / `raw_string_literal` handled in tree-sitter so const-string arg extraction works for Go's double-quoted and backtick forms.

### Symbolic Execution

- Expression trees (`SymbolicValue`) preserve computation structure through the path walk: integers, strings, binary ops, concatenations, calls, phi merges.
- Witness strings reconstruct concrete attack payloads at sink nodes.
- Bounded multi-path forking with reachability pruning.
- Cross-file: callee summaries are modeled directly, and pre-lowered callee bodies are loaded from SQLite so witnesses can keep walking across files.
- Interprocedural mode: nested frames with full state propagation, transitive descent up to 3 levels, structured cutoff tracking.
- Field-sensitive symbolic heap with bounded fields per object.
- Symbolic string theory: `Substr`, `Replace`, `ToLower`, `ToUpper`, `Trim`, `StrLen` modeled with concrete folding and sanitizer pattern detection.
- Optional Z3 integration (compile-time `smt` feature) for cross-variable constraint solving.

### Security & Coverage

- Vulnerability classes added: SSRF (10 languages), deserialization (Python, Ruby, Java, PHP), and `Cap::UNAUTHORIZED_ID` for auth-as-taint (off by default behind config flag).
- Auth analysis: receiver-type sink gating, row-level ownership-equality detection, self-actor recognition (`let user = require_auth()`), sink classification (in-memory vs realtime vs outbound), helper-summary lifting, and SQL JOIN-through-ACL recognition.
- State analysis (resource lifecycle, use-after-close, leaks, unauthed access) is now on by default. RAII-aware for Rust and C++; recognizes Python `with`, Go `defer`, Java try-with-resources.
- Framework rule packs: Express, Flask/Django, Spring/JNDI, Rails. Per-language label depth significantly expanded.
- C/C++ taint depth: output-parameter source propagation, implicit definitions for uninitialized declarations.
- Negative test corpus (30 fixtures) and a 262-case benchmark with CI gates on rule-level Precision/Recall/F1.

### Detection metrics

- Aggregate rule-level F1 reaches **0.998** (P=0.995, R=1.000). All real-CVE fixtures fire; only one open FP (`go-safe-009`).
- Go: 98.0% F1 on the 53-case corpus (1 FP / 0 FNs).
- CVE-2023-3188 (owncast SSRF) now detects.

### CLI & Output

- `nyx serve`: local web UI on `localhost` only (refuses non-loopback binds).
- `--require-converged` filters out findings where the engine bailed early.
- Analysis-engine toggles graduated from `NYX_*` env vars to first-class flags and `[analysis.engine]` config: `--constraint-solving`, `--abstract-interp`, `--context-sensitive`, `--symex`, `--cross-file-symex`, `--symex-interproc`, `--smt`, `--parse-timeout-ms`. Old env vars still work when Nyx is consumed as a library.
- Confidence (`High`/`Medium`/`Low`) shown on every finding, including console headers.
- Engine notes surfaced in console (`[capped: N notes, over-report]`), JSON (`engine_notes`, `confidence_capped`), and SARIF (`result.properties.loss_direction`).
- Flow paths reconstructed step-by-step with file/line/snippet for each hop.
- Concrete attack witness strings synthesized by the symbolic executor.
- Primary sink locations now point at the callee's real sink line; caller call sites are preserved as flow steps.
- Richer scan progress: explicit stages, timing breakdowns, language counters, skipped/reused file counts.
- Tighter taint-finding deduplication.

### Hardening

- Centralized path containment rejects traversal, symlink escapes, and oversized reads across UI, debug, and triage routes.
- `nyx serve` validates `Host` headers, requires per-session CSRF tokens for mutations, and refuses scans outside the original repo root.
- Walker re-validates symlink targets against the scan root.
- Bounded reads on framework manifests and `.nyx/triage.json` imports.
- UI falls back to plain text on pathologically long lines to defeat regex-DoS in syntax highlighting.
- Parser timeout is now configuration-backed with hostile-input regression coverage.

### Persistence

- SQLite schema bumped to v2. Anonymous-function identity is now a structural DFS index instead of a byte offset, so inserting a line above an unchanged function no longer invalidates its `FuncKey`. Pre-0.5.0 caches are silently cleared on open; triage data and scan history are preserved.
- Engine-version metadata; persisted summaries and file hashes invalidate on mismatch.
- Stale SSA tables recreate when required columns are missing; deserialization failures log instead of silently dropping rows.

### Frontend

- Replaced the legacy `app.js` with a React + Vite + TypeScript SPA.
- Interactive graph workspace for CFG and call-graph views (Graphology + ELK + Sigma) with neighborhood reduction and a full-page inspector.
- Triage UI with database-backed decisions (true positive, false positive, deferred, suppressed) and `.nyx/triage.json` round-trip.
- Scan history, rules management, and finding detail panels with evidence and flow visualization.
- Vitest browser-side test suite wired into CI.
- Bumped to React 19, Vite 8, TypeScript 6.0, ESLint 10, `@vitejs/plugin-react` 6, with aligned `@types/react*`.
- `SSEContext`: typed `reconnectTimer` ref as `ReturnType<typeof setTimeout> | undefined` to satisfy TS 6's stricter `useRef` overloads.
- `FindingsPage`: included `toast` in `useCallback` deps to avoid stale-closure warnings.
- `tsconfig.json`: dropped `baseUrl`, using a relative `./src/*` path mapping instead.

### Removed

- Legacy BFS taint engine, `TaintTransfer`, `TaintState`, and the `NYX_LEGACY` fallback.
- Legacy vanilla-JS frontend (`app.js`).

## [0.4.0] - 2026-02-25

A precision and ergonomics release. Findings are now ranked, lower-noise by default, and easier to triage in CI.

### Highlights

- **Attack-surface ranking.** Every finding gets an exploitability score combining severity, analysis kind, evidence strength, and path-validation. Console output shows the score in the header line; `--no-rank` opts out.
- **Low-noise prioritization.** Quality-category findings are excluded by default (`--include-quality` brings them back). High-frequency Quality rules are rolled up per `(file, rule)` with example occurrences. LOW budgets cap noise without ever displacing High/Medium findings.
- **State-model dataflow analysis.** New per-variable resource-lifecycle and auth-level analysis catches use-after-close, double-close, must-leak, may-leak (branch-aware), and unauthenticated-sink access. Opt-in via `scanner.enable_state_analysis`.
- **Inline `nyx:ignore` suppressions** with same-line and next-line directives, comma lists, wildcard suffixes, and string-literal guards across all 10 languages.
- **AST pattern overhaul.** All 10 language pattern files rewritten with consistent metadata, namespaced IDs (`<lang>.<category>.<specific>`), and 30+ new patterns. 11 broken tree-sitter queries fixed.
- **Monotone forward-dataflow taint engine.** Replaced the BFS engine with a proper worklist over a finite lattice. Termination is now guaranteed by lattice height, eliminating BFS-budget bailouts on large files.
- **Path-sensitive taint analysis.** Branch predicates flow with the analysis. Contradictory guards prune infeasible paths; validation calls produce annotated findings without changing severity.
- **Interprocedural call graph.** Whole-program graph with three-valued callee resolution (`Resolved`/`NotFound`/`Ambiguous`), SCC analysis, and topo ordering ready for bottom-up taint propagation.

### CLI & Output

- `--severity <EXPR>` replaces `--high-only`. Supports `HIGH`, `HIGH,MEDIUM`, `>=MEDIUM`. Filtering is now applied at the output stage so taint and CFG findings are correctly downgraded too.
- `--mode <full|ast|cfg|taint>` replaces `--ast-only` and `--cfg-only`.
- `--index <auto|off|rebuild>` replaces `--no-index` and `--rebuild-index`.
- `--fail-on <SEVERITY>` for CI exit-code gating.
- `--min-score <N>` for ranking-aware filtering.
- `--show-suppressed` reveals suppressed findings dimmed with `[SUPPRESSED]`.
- `--keep-nonprod-severity` (renamed from `--include-nonprod`).
- `--quiet` mirrors `output.quiet`.
- Console renderer overhauled: severity is the strongest visual anchor, file paths are dim blue, taint flows use `→` arrows, multi-line call chains are normalized.
- Confidence shown alongside score in the header line.
- Pattern-level confidence is now set at the pattern definition site, not heuristically inferred from severity.

### Breaking

- Config and data directory renamed from `dev.ecpeter23.nyx` to `nyx`. Existing config and SQLite indexes at the old path won't be picked up. Copy them across or re-run `nyx scan`.
- `Severity::from_str` now returns `Err` for unknown values instead of silently defaulting to Low.

### Notable Fixes

- KINDS-map audit across all 10 languages: 89 missing tree-sitter node types added. Switch/case, try/catch/finally, class bodies, lambdas, closures, and namespaces are no longer silently dropped.
- `else_clause` mapping fixed for C, C++, Rust, JS, TS, Python, PHP. Code inside else blocks was being dropped from the CFG.
- Rust `if let` / `while let` taint propagation now works.
- Taint BFS non-termination on large JS files (the BFS engine has since been replaced).
- C++ `popen` pattern ID collision with C.
- Constant-arg sink suppression for AST patterns.

## [0.3.0] - 2026-02-25

Configurability, SARIF, and an aggressive false-positive purge.

### Highlights

- **Configurable analysis rules.** Sources, sanitizers, sinks, terminators, and event handlers can be defined per language in `nyx.local` or via `nyx config add-rule`/`add-terminator`. Config rules take priority over built-in rules.
- **`nyx config` CLI subcommand** with `show`, `path`, `add-rule`, `add-terminator`.
- **SARIF 2.1.0 output (`-f sarif`).** Spec-compliant for GitHub Code Scanning, Azure DevOps, and other SARIF consumers.
- **`SourceKind` taint classification.** Findings carry an inferred source kind (`UserInput`, `EnvironmentConfig`, `FileSystem`, `Database`, `Unknown`) and severity is now derived from it instead of being hardcoded to High.
- **Non-prod severity downgrade by default.** Findings in tests, vendor, benchmarks, examples, fixtures, build scripts, and `*.min.js` are downgraded one tier. `--include-nonprod` restores original severity.
- **Resource leak detection** for Python, Ruby, PHP, JavaScript, and TypeScript (file handles, sockets, locks, mysqli, curl, fs streams).
- **Progress bars and quiet mode.** Indicatif-driven progress for discovery, Pass 1, and Pass 2 (auto-hidden in JSON/SARIF/quiet modes).

### Performance

- Single fused parse+CFG pass replaces the previous two-parse summary extraction.
- Light-weight dataflow sweep in CFG builder is now O(N) per function instead of O(N²) over the whole file.
- Parallel summary merging via rayon fold/reduce.
- Indexed scans now read and hash each file once instead of up to 4 times.
- SQLite mutex mode relaxed (r2d2 + WAL provides safety without global lock).
- Zero-allocation taint hashing and in-place taint transfer.

### Notable Fixes

- One-hop constant-binding suppression: `cmd = "git"; subprocess.run([cmd, ...])` no longer flags.
- Exec-path guards (`which`, `resolve_binary`, `shutil.which`) recognized.
- `signal.connect` / `event.connect` no longer match Python db-connection acquire patterns.
- `threading.Lock()` without `.acquire()` no longer flags as unreleased.
- `FileResponse(f)` / `send_file(f)` recognized as ownership transfer.
- `el.href` no longer matches `location.href` patterns.
- Constant-only sink calls (`subprocess.run(["make","clean"])`) suppressed.
- `std::cout` no longer treated as a sink.
- Break/continue inside loops correctly wires into the loop header/exit, fixing false unreachable-code findings.
- Preprocessor `#ifdef`/`#endif` blocks no longer orphan subsequent code in C/C++.
- `freopen` no longer matches `fopen` acquire patterns.
- Struct-field, linked-list, and global assignment recognized as ownership transfers.

## [0.2.0] - 2026-02-24

The cross-file release.

- **Two-pass cross-file taint analysis.** Pass 1 extracts `FuncSummary` per function (caps, propagation, callees), Pass 2 runs BFS taint propagation with cross-file callee resolution.
- **CFG analysis engine** with five detectors: unguarded sinks, auth gaps in web handlers, unreachable security code, error fallthrough, resource leaks.
- **Cross-language interop** via explicit `InteropEdge` structs (no false-positive name collisions).
- **Function summaries persisted to SQLite** (`function_summaries` table).
- **Multi-language CFG + taint support** for all 10 languages.
- **Resource leak detection** for C/C++, Go, Rust, and Java.
- **Finding scoring system** combining severity, entry-point proximity, path complexity, taint confirmation, and confidence.
- **Analysis modes**: `Full` (default), `Ast` (`--ast-only`), `Taint` (`--cfg-only`).
- **Cap bitflags expanded**: `ENV_VAR`, `HTML_ESCAPE`, `SHELL_ESCAPE`, `URL_ENCODE`, `JSON_PARSE`, `FILE_IO`.
- Performance: read-once/hash-once via `_from_bytes` variants, lock-free rayon, SQLite WAL + 8 MB cache + 256 MB mmap.
- Tracing instrumentation on all pipeline stages; criterion benchmark suite.

## [0.2.0-alpha] - 2025-06-28

- Experimental intra-procedural CFG + taint analysis for Rust. Builds a CFG, applies dataflow, and flags unsanitised Source → Sink paths (e.g. `env::var` → `Command::new`).
- O(1) node-kind lookup via per-language PHF tables.
- Debug channel `target=cfg` (`RUST_LOG=nyx::cfg=debug`) to inspect generated graphs.
- Fixed Windows release pipeline (PowerShell has no `zip` command).

## [0.1.1-alpha] - 2025-06-25

- Fixed `scan --no-index` not respecting the `max_results` config setting (#1).
- Integration tests covering indexing and scanning pipelines (#3, #4, #5, #8).

## [0.1.0-alpha] - 2025-06-25

Initial alpha release.

- Multi-language AST pattern scanning via `tree-sitter` for Rust, C/C++, Java, Go, PHP, Python, Ruby, TypeScript, JavaScript.
- `scan` command: filesystem walker, pattern execution, console output.
- `index` command: build, rebuild, and status reporting of SQLite-backed index.
- `list` command: list indexed projects with optional verbosity.
- `clean` command: remove one or all project indexes.
- Configuration system with `nyx.conf` (generated) and `nyx.local` (user overrides).
- Default severity levels: High, Medium, Low.
