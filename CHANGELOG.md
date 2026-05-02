# Changelog

All notable changes to Nyx are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For where Nyx is going, see the [Roadmap](ROADMAP.md).

## [Unreleased]

## [0.6.0] - TBD

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
