# Changelog

All notable changes to Nyx are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For where Nyx is going, see the [Roadmap](ROADMAP.md).

## [0.9.0] - 2026-11-22

The accuracy and speed release. Pass 2 now analyses files in parallel, so large repos scan in a fraction of the time: keycloak goes from 660 s to about 30 s, Ghost from 304 s to about 20 s and strapi from 140 s to about 15 s, and gogs and roundcube no longer time out. Indexed rescans re-analyse only what changed, so rescanning strapi after a one-file edit takes about 3 s.

Security findings on 23 open-source repos drop by more than a third, almost all of them false positives, and every language gets recall fixes. The benchmark corpus grows from 674 to 1279 cases, including 23 new CVE pairs, and scores TP 655, FP 0, FN 0, TN 610.

### Behaviour changes

- **Rust 1.89 is the minimum supported version** (was 1.88).
- **JSON responses are not XSS sinks.** Express `res.json(..)` and a Koa `ctx.body` set to an object or array literal are sent as `application/json`, so they no longer report as HTML injection. A `res.json` in a handler that sets a `text/html` content type, `res.send`, and a string `ctx.body` still do.
- **Test mocks no longer report on production code.** A mock request built in a test file (`req.query = {..}`) that reaches a sink in a production file is no longer reported; the production flow is reported from the production file's own sources. `--keep-nonprod-severity` (alias `--include-nonprod`) keeps these findings.
- **Test and non-production paths are classified relative to the scan root.** A checkout under `/opt/build` or `~/test` is no longer downgraded as a whole, and `_test.go`, `_spec.rb`, RSpec and JS `spec/` trees and Cucumber step definitions now count as test code wherever they live.
- **`.mjs`, `.cjs`, `.mts` and `.cts` files are scanned.**
- **Inline `nyx:ignore` works everywhere.** It now applies in `.jsx` and C++ header files, on Rust lines that contain a lifetime, and in `nyx serve` and library scans, not only the CLI.
- **Findings come out in a stable order.** Output order, which duplicate flow survives and `max_results` truncation no longer depend on the run's call-graph batch order.
- **Indexed scans drop cached summaries when analysis settings change.** Adding a custom sink in `nyx.conf`, a framework to a manifest, or switching mode no longer leaves unchanged files on stale summaries.

### Performance

- **Parallel pass 2.** Files are analysed by dependency level instead of one at a time, SCC batches converge cheaply, and false self-recursion no longer forces extra rounds.
- **Incremental rescans.** An indexed rescan reuses the pass-2 result of every file whose contents are unchanged and whose cross-file lookups still return the same summaries. Only edited files and the callers whose inputs they changed are analysed again, and findings match a full `--index off` scan. A rescan with no edits drops from 9.7 s to 1.2 s on gitea and from 12.1 s to 1.6 s on strapi, and a one-file edit takes 1.2 to 1.8 s on gitea and 1.8 to 2.1 s on strapi. Cross-file callee bodies are stored with their fingerprints and stay encoded in memory until an analysed file reads one. An edit that leaves a function's summary unchanged, such as a comment, re-analyses only that file. So does an edit that only moves functions down their file, unless a caller's finding points inside one of them, and a new function whose name other functions already use, unless it changes what an existing call resolves to. The first indexed scan no longer runs a separate index build, and surface-map probes are cached by file hash. The index database grows by 10 to 45% to hold the cache. `NYX_INCREMENTAL_VERIFY=1` re-analyses every reused file and logs any difference from the cached result, and `NYX_INCREMENTAL_EXPLAIN=1` logs which lookups changed for each file analysed again.
- **Less time on one core.** The surface-map build probes files in parallel, pass-2 files start largest first so one huge file no longer runs alone at the end, analysis options are read lock-free, long chained callee texts are normalised once, the Express route witness is computed once per file, canonicalised paths are cached in the module graph, data-store and external-service rules are matched through a prebuilt index instead of lowercasing every rule for every callee, and a file's package is found by walking up its folders instead of testing every package root.
- **Per-node work.** Constant propagation runs over per-instruction use lists, post-dominators are built once per body without copying the CFG, callee resolution reuses candidate lists and callee facts across a run, engine option scalars are resolved once instead of per call, and closure children a parameter never reaches are skipped.
- **Tree-sitter calls.** The CFG builder reads node kinds and their classes from a per-file table indexed by `kind_id()` instead of converting the grammar's C string on every call, walks call-argument nesting with one top-down cursor descent instead of `parent()`, and the label suffix matcher is always inlined.

### Fewer false positives

- **Taint sources.** Writing to `req.path` or `req.headers[k]` no longer makes them a source. Caught exceptions only reach output, header, template, format and shell sinks, not SQL, file, SSRF, redirect or prototype-pollution sinks. Java `getContextPath()` is not request input. Rails `*_path` helpers, `URL.searchParams` writes and the page's own `location.origin` no longer count as redirect sources.
- **JS/TS closures.** Variables local to one handler no longer leak into sibling closures through the file's top-level scope. `this.field` writes are not globals. Reading `obj[key]` takes the taint of `obj`, not of `key`. Params with handler-like names are only seeded when the function has no known caller.
- **Validation.** `startsWith(root) === false` and similar negated or sentinel checks are read the right way round. Allowlists checked with `==`, comma-ok, `slices.Contains` or a ternary now validate the value they test. Multiline and alternation regexes are not treated as anchored.
- **Path containment.** A string prefix check only proves containment when the root ends in a separator, since `/srv/data` also admits `/srv/data-x`. `Path.startsWith`, `Path::starts_with` and `is_relative_to` compare components, so any root works. The check has to hold after `..` is normalised away.
- **SSRF and redirects.** Origin locks have to hold on every path to the sink, and now follow URL builders and more fixed-host string shapes. A same-host check on a parsed URL clears both redirect and SSRF taint. Open redirect needs a protocol-relative rejection (`//evil.com`) before it is cleared. Host denylists and `IsHostnameInternal` / `safe_for_redirect` style helpers count as guards.
- **Authorization ownership.** These now count as owned: ids read off a row the handler already loaded or just inserted, gitea `ctx.Repo`, session user ids, the signed-in user, Redmine `Model.visible` scopes, querysets scoped to the caller, and owner checks on a fetched or parent row.
- **Authorization frameworks.** Rust `is_admin(..)?` gates, axum and actix-web layers, Spring security annotations (including role alternatives), Rails `only:` / `except:` filter lists, CanCanCan class macros, Django view decorators and DRF class views without a `urls.py`. Django migrations, private helpers, Mirage mock servers and JS/TS test files no longer report.
- **Resource leaks.** Null and error branches are pruned. A handle that is returned, stored, wrapped or added to a collection counts as handed off. Releases inside `if` conditions count. Python cursors are treated like JDBC statements. Same-file close wrappers, sub-object aliases, cast views and `pipe` hand-offs are followed. Use after close only reports the handle that was closed.
- **`cfg-unguarded-sink`.** Ruby ActiveRecord chains are checked as a whole statement, so `reorder(nil)`, Arel, `select(1)` and table-name-only SQL stay quiet. So do project methods named `eval`, Go `db.Exec(ctx, sql, ..)`, constant collections in interpolation, constant `Sequelize.literal` calls, PHP numeric casts, Ruby `shellescape` and writes to a declared file stream.
- **Control flow.** `finally` and `ensure` run on return paths. `match`, `select`, `case` and arrow `switch` are exclusive branches. `x += 1` and `x++` read `x` before writing it. Framework abort helpers end the request. `err == nil` is a success check in `cfg-error-fallthrough`.
- **Pattern rules.** Java `execute(..)` concat needs a SQL-shaped call. `java.reflection.method_invoke` needs a `Method` receiver. Ruby `send` over a fixed set of literals, lossless Rust narrowing casts, and `res.sendFile` / `res.download` with a literal root stay quiet. File-write sinks check the path, not the content written. The CORS, `secure: false`, location, cookie and error patterns, and EJS partials, skip their safe forms.
- **Per language.** JS/TS `child_process` sinks need the import. Go HTTP clients, response writers and request sources are typed from their declarations. Python labels follow `from` imports and DB-API `execute` is gated on the query argument. Bound SQLAlchemy statements and bound Rust SQL parameters are not injection. JS/TS query builders, tagged SQL and config-object queries are checked for where the values come from, and `orderBy` keys must be static.

### New detections

- **PHP.** `echo` / `print` / `<?=` of a direct superglobal (`echo $_GET['q']`) now reports, as do ternary `echo` operands. FILE_IO builtins (`unlink`, `rename`, `mkdir`, `readfile`, `file`, `scandir` and more), dbFacile SQL helpers with the parameter array as the safe channel, and `$x = !call(..)` are modelled.
- **C/C++.** Pointer-returning function declarators (`char *f(char *x)`) keep their parameters, a call assigned inside a condition (`if ((x = getenv(..)) == NULL)`) is lowered, functions inside `#if` groups are analysed, arity-suffixed wrapper macros keep their argument layout, and calls through local function pointers no longer resolve to unrelated globals.
- **Java.** Statement-form `StringBuilder.append`, Spring handlers that return HTML, Netty file sinks, path-view `startsWith` chains, path taint through `File` and `String` constructors, and `Paths.get` as a static call.
- **JS/TS.** Member paths longer than three segments (`event.node.req.url`), Koa `this.redirect` and prototype handlers, Astro sources, `$fetch` sinks, missing Node sinks, browser redirects as open redirects, and header setters as header injection.
- **Python and Ruby.** `Popen` shell arrays and shell kwargs, FastAPI query parameters, default markers and Pydantic bodies as sources, Ruby optional and keyword parameters bound by name, ActiveRecord `connection.execute` chains, and bare zero-arity calls as sink arguments. Ruby argv-form `system` is not a shell.
- **Go and Rust.** Origin locks through `strings.Trim`, `ReplaceAll` and `Sprintf`, struct fields declared as requests, missing Go sinks, Rust reads from an open `File` as a source, `toml` / `ron` decode into a `dyn` target through a `let` annotation, rusqlite handles in struct fields and `Arc<Mutex<Connection>>`, and every path spelling of the unsafe memory primitives.
- **Mongoose.** An actor id in the update document of `findOneAndUpdate` / `updateOne` no longer suppresses the missing ownership check on the filter.

### CVE corpus and ground truth

- 23 new vulnerable/patched pairs built from upstream fix commits: CVE-2022-48624, CVE-2024-23819, CVE-2024-32461, CVE-2024-42352, CVE-2024-49760, CVE-2025-15379, CVE-2025-53623, CVE-2025-54314, CVE-2025-58179, CVE-2025-6023, CVE-2025-62595, CVE-2025-66645, CVE-2025-71405, CVE-2025-8129, CVE-2026-112049, CVE-2026-25554, CVE-2026-28415, CVE-2026-34375, CVE-2026-41058, CVE-2026-46671, CVE-2026-8274, CVE-2026-85396, CVE-2026-85439.
- Previously disabled cases that now pass: `ruby-sqli-raw-001`, `cve-go-2023-3188-patched`, `cve-go-2024-37896-patched`, `cve-ruby-2026-40295-vulnerable`.
- Two former safe cases (`py-safe-022`, `js-safe-021`) were real sibling-prefix bugs and are now vulnerable cases with separator-terminated safe twins.
- 14 cases stay disabled, each with the missing capability named in `ground_truth.json`.

### Fixes

- AST-pattern rules fire on both `.ts` and `.tsx` files. The two share a language slug but not a grammar, and the compiled query cache was keyed by slug only, so one of the two file types got no AST-rule hits.
- A PHP file with a long chain of `@`, unary operator or parenthesis wrappers no longer hangs the scan. The call search visited each level of the chain once per path to it, so the time grew exponentially with its length.
- `nyx scan <file>` no longer fails with "triage sync failed: scan root is not a directory". A single-file scan reads the triage file of the enclosing project (nearest `.nyx/triage.json`, stopping at the repository root).

### Dependencies

- `chrono` is replaced by `jiff` 1.0 (timestamps keep the `+00:00` RFC 3339 format). `rusqlite` 0.41 (with `r2d2_sqlite` 0.36), `tokio` 1.54, and `h2` 0.4.20 for RUSTSEC-2026-0258.

### Known limitations

- argv and `ARGV` are not taint sources; CLI trust is a separate policy decision.
- Path containment reasoning assumes POSIX separators.
- Known false positives: `describe` / `it` closure flows in express tests, mastodon `redirect_to streaming_api_url`, redmine `order(options[:order])` on caller-supplied options, and `window.location.origin + pathname`.

## [0.8.0] - 2026-08-13

The dynamic-verification release. An attack-surface map, a sandboxed dynamic verifier, a framework adapter registry that grounds both, the per-language build infrastructure that makes per-finding verification affordable at corpus scale, and the first real-corpus acceptance gates.

Alongside it, a static-engine accuracy and throughput campaign. Measured against the previous engine on an identical 669-case corpus, false positives drop from 43 to 0 and false negatives from 20 to 1 (rule-level F1 0.906 to 0.998), while a full scan of a 492-file Go service runs 1.35x faster and reports more findings than before.

The attack-surface map and chain composer turn the flat finding list into a route-to-sink graph. The dynamic verifier re-runs every Medium-or-higher finding against a payload corpus and stamps a Confirmed / PartiallyConfirmed / NotConfirmed / Inconclusive / Unsupported verdict on each. The adapter registry (130+ entries across 8 languages) covers HTTP, message-broker, scheduled-job, GraphQL, WebSocket, middleware, and migration entry points. Per-language build pools and copy-on-write workdirs hold the with-verify wall-clock to within 1.5x of a static-only scan.

### Attack-surface map

- **`nyx surface` subcommand.** Prints the project's entry points, datastores, external services, and dangerous local sinks as text, JSON, Graphviz `dot`, or rendered SVG. Loads the persisted `SurfaceMap` from the most recent indexed scan when available, or rebuilds inline from source. `--build` forces a full pass-1 + call-graph walk so DataStore / ExternalService / DangerousLocal nodes populate on an unscanned project.
- **Surface page in `nyx serve`.** New `SurfacePage` renders the same graph in the browser UI, with ELK layout, sidebar navigation, and a wide-canvas SVG viewer. Persists alongside the index so the frontend reloads without a rescan.
- **Chain findings.** `ChainFinding` records connect a route entry point to a downstream sink via the call graph + surface map. The composer scores `(impact × evidence)` per chain, queues the top-N for composite reverification, and wires the result into `findings.json` / SARIF / the dashboard. Chains rank above isolated findings.
- **Per-finding exposure.** A finding reachable from an externally-facing route now carries the worst-case route that drives it, surfaced as an `Exposure` record (route, method, framework, auth state, and whether the reach is direct or transitive through the call graph). Findings with no reaching entry point, and all findings when the project has no detected entry points, carry no record, so an absent `Exposure` means "not connected", not "safe". Unauthenticated routes win over auth-gated ones and direct file matches win over transitive ones. The annotation shows up as an `Exposure:` evidence line in console output and on `findings.json`, SARIF `properties.exposure`, and the server finding view. Ranking adds a bonus for it, so a finding reachable from an unauthenticated route sorts above an otherwise-equal internal one.
- **Entry-point risk scoring.** `nyx surface` opens with a risk-sorted "Top risk entry-points" banner and tags each route with a `low` / `medium` / `high` / `critical` tier. The score is explainable: the worst reachable sink class dominates, writing a store outranks reading it, talking to an external service and mutating HTTP methods add, and missing auth multiplies the whole exposure. The `/api/surface` response carries the same `entry_risks` array so the browser UI renders the ranking without re-deriving it.
- **Function-level reachability with typed edges.** Reachability now matches a destination to an entry point when the owning function is on the call-graph frontier, not merely when they share a file, so two unrelated handlers in one file no longer both claim a co-located `eval()`. Edges are typed by destination: `ReadsFrom` / `WritesTo` for a datastore (split by the access direction inferred from the call verb, so a route that writes SQL reads differently from one that only queries), `TalksTo` for an external service, `Reaches` for a dangerous local sink. The pass falls back to the same-file heuristic when the handler seed cannot be resolved in the call graph, or when a destination loaded from an older persisted map predates the owning-function field.
- **Richer surface nodes.** `DangerousLocal` carries a decoded sink-class label (`code-exec`, `deserialize`, `ssti`, ...) and a real sink span instead of a raw cap bitfield at line 0. `DataStore` and `ExternalService` carry the qualified name of the owning function. The dangerous-local sink set widened from four classes to ten, adding LDAP injection, XPath injection, header injection, open redirect, XXE, and prototype pollution, and datastore / external detection gained cap-driven fallbacks (`SQL_QUERY` / `FILE_IO` and `SSRF` / `DATA_EXFIL`) so a custom DAO wrapper or proxy helper still surfaces when no named driver matched.
- **Entry-point and auth recall.** Handlers the framework probes miss but pass-1 already tagged as entry points are synthesised into the surface map so the entry set is a superset of what the taint engine treats as adversary-driven. `auth_required` upgrades when a handler's own body calls a known auth guard, complementing the router-level decorator / annotation / middleware detection.
- **Coverage telemetry.** A fresh `nyx surface` build prints a coverage line (files seen, files in a supported language, files parsed, files with routes, plus unparsed / unreadable counts) so a small map can be told apart from "the probes did not understand this project". A loaded persisted map reports node and edge counts and points at `--build` for a source rebuild.

### Framework adapter registry

`src/dynamic/framework/` ships a `FrameworkAdapter` trait with concrete adapters across 8 languages (116 entries today, growing per release). Each adapter binds a route / handler / consumer pattern to a `FrameworkBinding` so the surface map and dynamic verifier can locate entry points without re-walking the AST.

- **HTTP routers.** Flask, Django, FastAPI, Starlette (Python); Express, Koa, NestJS, Fastify (JS/TS); Spring, Quarkus, Micronaut, Jakarta Servlet (Java); Gin, Echo, Fiber, Chi (Go); Axum, Actix, Rocket, Warp (Rust); Rails, Sinatra, Hanami (Ruby); Laravel, Symfony, CodeIgniter (PHP).
- **New `EntryKind` variants.** `ClassMethod`, `MessageHandler`, `ScheduledJob`, `GraphQLResolver`, `WebSocket`, `Middleware`, `Migration` join the existing `RouteHandler` / `Function` set so the surface map shows non-HTTP entry surfaces.
- **Message broker handlers.** Kafka, AWS SQS, Google Pub/Sub, NATS, and RabbitMQ consumers across Python, Node, Java, and Go.
- **Scheduled jobs.** Celery (Python), Sidekiq (Ruby), Quartz (Java), plain cron expression recognition.
- **GraphQL resolvers.** Apollo, Relay, gqlgen, Juniper, Graphene.
- **WebSocket handlers.** ws, Socket.IO, ActionCable, Django Channels.
- **Middleware + migrations.** Express, Laravel, Spring, Django, Rails middleware; Django, Flask, Laravel, Rails, Prisma, Sequelize migration scripts.
- **Sanitizer-aware adapter strengthening.** Every XXE, header-injection, open-redirect, SSTI, LDAP, XPath, deserialization, crypto, and data-exfiltration adapter rejects bindings when the surrounding source visibly hardens the parser (`disallow-doctype-decl`, `resolve_entities=False`, `libxml_disable_entity_loader`), routes the value through a known encoder (`LdapEncoder.filterEncode`, `escape_filter_chars`, `ldap_escape`), swaps a weak primitive for a CSPRNG (`secrets.token_bytes`, `crypto.randomBytes`, `SecureRandom`), or validates the destination host through an allowlist. Cuts adapter FPs without losing the genuinely dangerous calls.

### Dynamic verification

- **`nyx scan --verify`.** Every finding with `Confidence >= Medium` is re-executed inside a sandboxed harness against a curated payload corpus. The verdict (`Confirmed` / `NotConfirmed` / `Inconclusive` / `Unsupported`) lands on `Evidence.dynamic_verdict` and shows up in console output, JSON, SARIF, and the dashboard via a new `VerdictBadge` component on the finding detail page.
- **Backends.** In-process on Linux with `Standard` / `Strict` hardening (namespace unshare, chroot, RLIMIT cap, seccomp filter), in-process on macOS via `sandbox-exec` with a profile-per-policy wrap, Docker with a published image-builder catalogue, and a Firecracker trait stub for future microVM execution. The Docker backend ships native binary support for Rust and Go so harnesses no longer need to drag a toolchain into every image.
- **Language coverage.** Per-language harness emitters for Python, JS/TS, Go, Java, PHP, Ruby, Rust, C, and C++. Stub harness intercepts SQL, HTTP, Redis, and filesystem boundaries so the verdict reflects the sink, not the network. The `JSON_PARSE`, `UNAUTHORIZED_ID`, and `DATA_EXFIL` cap dispatchers are wired into every emitter that ships these caps (Python, JS, TS, Go, Java, PHP, Ruby, Rust), so the verdict pipeline closes the loop on each cap end-to-end rather than per-language piecemeal.
- **Abstract-interpretation and symex sanitizer suppression.** Symbolic execution and the interval/string abstract domain are now consulted at verdict time, so a payload that the static engine would call dangerous but symex can prove never reaches the sink lands as NotConfirmed.
- **Guard-aware verdicts.** When a known input-validation or output-sanitization middleware sits in front of a Confirmed sink (Spring `@PreAuthorize`, Express `helmet`, Nest `@UseGuards`, Django `@permission_classes`, and the per-language registry in `src/dynamic/framework/auth_markers.rs`), the verdict demotes to `ConfirmedWithKnownGuard` and the guard names land on `differential.known_guards`. Authentication-only filters do not trigger the demotion since they do not mitigate injection.
- **Repro bundles.** Every verified finding writes a hermetic bundle to `~/.cache/nyx/dynamic/repro/<spec_hash>/` with `reproduce.sh`, `expected/{verdict.json,outcome.json,trace.jsonl}`, and a `docker_pull.sh` when the toolchain is pinned in `tools/image-builder/images.toml`. `--verbose` flushes the per-step `VerifyTrace` to stderr for live triage.
- **Real-engine harness paths.** LDAP injection routes through an embedded LDAPv3 BER server, exercised from Java via JNDI `InitialDirContext` and from Python and PHP via pure-stdlib BER clients. XPath injection runs against the live parser in each language: Java `javax.xml.xpath`, PHP `DOMXPath`, JS `xpath` npm, Python `lxml`. `Cap::CRYPTO` lands a `WeakKey` probe across Python, Go, Java, PHP, and Rust that flags sub-2^16 keys produced by non-CSPRNG sources. A new `HeaderSmuggledInWire` oracle predicate catches CRLF smuggling on hand-rolled raw-socket HTTP servers (Python `http.server`, Node `net`, Rust `std::net::TcpListener`) where framework-level CRLF strip cannot intervene.
- **Differential rule v2 and partial confirmations.** A finding confirms when *any* vulnerable payload in the set fires and *every* paired benign control stays clean, replacing the strict pair-wise rule so a single missing control no longer downgrades a confirmable finding. A new `PartiallyConfirmed` verdict marks findings where the sink is reached but the exploit chain does not complete (no marker written, no callback observed), so engine work can ratchet without the tool overstating what it proved.
- **Spec derivation v2.** Every derivation strategy now runs and is scored on flow-step depth, framework binding, cross-file source resolution via `GlobalSummaries`, and payload availability; the highest-scoring candidate wins and the runner-up ranking lands in the trace so engine gaps stay visible. Cross-file seeding walks the call graph (max depth 5) until a `Source` step or framework binding is found. New `EntryKind` adapters auto-recover the entry surface from framework decorators and annotations.

### Performance

- **Per-language build pools.** A warm `javac` daemon compiles batched harness sources in one long-lived JVM (Track O headline, Phase 22); Node, PHP, Ruby, Go, Rust, C, and C++ reuse shared module / package / object caches; Python layers a read-only venv per `requirements_hash` with a warmed bytecode cache. Target per-finding harness build: P50 ≤ 200ms hot, ≤ 1.5s cold. Pools self-skip when a toolchain is absent so toolchain-less CI rows stay green.
- **Copy-on-write workdirs.** Per-finding workdir setup uses `clonefile` on macOS and `reflink` / `copy_file_range` on Linux instead of copying every harness file, cutting setup cost to single-digit milliseconds.
- **Cap-routed concurrency lanes.** The verifier worker pool splits into per-cap lanes (`SSRF: 8`, `DESERIALIZE: 2`, `CRYPTO: 1`, and so on) so a slow harness for one cap cannot head-of-line block fast ones.
- **Ship-gate budgets.** Gate 3 holds the with-verify / static-only wall-clock ratio at ≤ 1.5x on `benches/fixtures/`; Gate 6 holds the Java OWASP Benchmark `--verify` run at ≤ 15 min on CI / ≤ 10 min on the dev reference machine.

### Determinism, policy, telemetry

- **YAML policy deny list.** `src/policy.rs` is consulted before harness build. Network egress, filesystem writes outside the sandbox root, and process spawns can be denied per-rule; deny decisions land in the trace, redacted via the shared scrubber.
- **Seeded RNG.** `dynamic::rand::SpecRng` is seeded from each `HarnessSpec` hash so two runs of the same spec produce identical payloads. `scripts/check_no_unseeded_rand.sh` audits the tree for unseeded `rand` usage on every CI run.
- **`VerifyTrace` observability.** Every per-step decision (probe selection, payload mutation, oracle check, deny verdict) writes to the trace stream and the repro bundle.
- **Schema-versioned telemetry.** `events.jsonl` carries `schema_version`, `nyx_version`, `corpus_version`, `kind`, and `ts` on every envelope. PII and secret scrubbing runs on every persisted artefact via `src/utils/redact.rs`.
- **`NYX_NO_TELEMETRY=1`** disables event persistence outright.

### CVE corpus and ground truth

- **New `Cap` corpora.** Vulnerable + patched fixtures landed for the seven new cap classes (LDAP injection, XPath injection, header injection, open redirect, SSTI, XXE, prototype pollution) plus deserialization, crypto, JSON parsing, unauthorized-id, and data exfiltration. Every cap now carries at least one positive / negative / adversarial / unsupported fixture quad per supported language.
- **OWASP Benchmark v1.2 importer.** `tests/eval_corpus/owasp_gt_convert.py` converts the OWASP Java Benchmark expected-results manifest into Nyx ground truth and lands a 16k-line `owasp_benchmark_v1.2.json` for evaluation.
- **NIST SARD importer.** `tests/eval_corpus/sard_gt_convert.py` converts SARD test cases into the same format so cross-dataset recall numbers stay comparable.
- **Evaluation corpus tooling.** `tests/eval_corpus/run_full.sh` runs the Nyx benchmark, OWASP Benchmark, and NIST SARD evaluation sets and writes `tests/eval_corpus/results.json`. `tests/eval_corpus/report.py` and `tabulate.py` produce the per-cap and per-language summary used to track coverage and accuracy.
- **Real-corpus acceptance gates.** `scripts/m7_ship_gate.sh` adds Gate 6 (Java OWASP Benchmark v1.2), Gate 7 (NodeGoat + Juice Shop), and Gate 8 (RailsGoat, DVWA, DVPWA, gosec, RustSec). Each row enforces the per-`(cap, lang)` budget in `tests/eval_corpus/budget.toml` and publishes per-cap precision / recall / confirmed-rate against a committed ground truth. The corpora are not vendored; each row self-skips unless its `NYX_<NAME>_CORPUS` points at a checkout.
- **Per-spec cryptographic canary.** Every oracle marker is now derived from `BLAKE3(spec_hash || run_nonce)` rather than a fixed literal, so markers are unique per finding, collision-resistant against ambient harness output, and never leak to the host. A compile-time audit rejects any new ad-hoc canary.

### Engine

- **DB fast-fail preflight.** `Indexer::init` reads the first 16 bytes of any candidate SQLite file and rejects anything without the standard `SQLite format 3\0` magic. Stops a misnamed JSON / text file from corrupting the index path with a SQLite error halfway through migration.
- **Symbolic-execution coverage.** Symex now recognises a wider set of string operations (`substr`, `replace`, `to_lower`, `to_upper`, `trim`, `strlen`) per the value/transfer pipeline, and the abstract-interpretation framework reasons about interval and prefix/suffix string facts during the dynamic verdict pass.

### Fixed (engine correctness)

- **CFG construction.** Python `if/elif/elif/else` chains no longer drop every alternative past the first, so a sink in a second `elif` or a trailing `else` is analysed (same fix covers PHP `else_if`). C-style `for (init; cond; incr)` loops now lower the initializer and increment, so taint introduced in the loop header (`for (cmd = getenv(...); ...)`) reaches the body. A `switch` `default` is no longer unconditionally hoisted to the chain tail, preserving fall-through order in C/C++/JS/TS/PHP/Java. Source/sink calls inside short-circuit `&&` / `||` operands of an `if` / `while` condition are now classified instead of dropped.
- **SSA lowering of exception handlers.** Catch blocks with internal control flow (an `if` / loop / nested `try` inside the handler) no longer lose every instruction past the catch entry: the orphan subtree is renamed through a virtual-root dominator tree, so sinks reached only inside a `catch` are seen. Catch-side variable reads now resolve to the most entry-dominating reaching definition (the pre-`try` value) rather than a post-join reassignment. A genuine positional argument equal to a chained-call receiver root (`a.b.m(p, a)`) is preserved instead of being stripped as the implicit chain root.
- **Taint soundness.** Sink suppression now gates on `validated_must` (validated on every path) instead of `validated_may` (any path), closing a false-negative where a single validated branch silenced a sink. `is_noreturn_call` no longer matches receiver-qualified `.exit()` / `.abort()` / method calls, so `transaction.abort()` stops wiping taint state. The SSRF same-origin check rejects protocol-relative `//host` prefixes (an open-redirect / SSRF bypass that a bare `/`-prefix check accepted). Inline-return taint unions the derived and parameter-passthrough channels for mixed-return helpers (`if (c) return src(); return x;`). The inline-analysis cache is keyed to exclude callback-bound arguments, so a function-valued argument no longer poisons sibling call sites that pass a different callback.
- **Taint precision.** `String.valueOf(String/Object)` is no longer tagged a safe-string producer (it is an identity passthrough, so `String.valueOf(req.getParameter(...))` was silently suppressed). Cross-parameter sanitizers no longer bleed onto sibling arguments (`f(a, b){ return a + escape(b) }` sanitises only `b`), and a cross-file sanitizer resolved through the coarse summary tier still applies its strip. Relative-URL and host-allowlist cap clearing is alias-aware. Substring-rejection and `indexOf() === -1` idioms are no longer misread as allowlist validation, and dotted multi-argument validators no longer over-validate unrelated targets.
- **Interprocedural resolution.** SCC / topo file batching and reachability key files by their package-qualified namespace, matching the call-graph nodes and SSA summary tier so cross-package callers resolve. Directly self-recursive functions now get SCC fixed-point treatment. Call resolution tolerates under-application (a call supplying fewer arguments than a callee with default / optional parameters) while still degrading to `Ambiguous` rather than a wrong pick. A failed SCC iteration no longer overwrites a file's cached diagnostics with an empty set. JS/TS module resolution appends extensions to dotted specifiers (`./user.service` → `user.service.ts`) and swaps a `.js` import to a `.ts` file (NodeNext / ESM).
- **JS/TS two-level solve.** Pass-2 top-level (global) taint now reaches nested closures two or more scopes deep, and the pass-2 dirty-skip no longer drops a nested body that transitively consumes a changed global through a parent-local.
- **Scan pipeline and index.** `replace_all_for_file` deletes stale SSA summary / body rows unconditionally, so an incremental rescan cannot leave orphaned rows. Cached findings recompute their category instead of being stamped `Security`, so structural warnings keep their real class. The indexed build persists auth summaries and cross-package imports, logs-and-skips an unreadable file instead of aborting the whole build, and keys `FuncSummary` entries to match the SSA tier so an indexed scan and a full scan agree.
- **Language coverage (recall).** KINDS maps were completed so previously-dropped bodies are walked: Java interface / enum / record / `synchronized` blocks, Rust inline `mod { ... }` items, Go labeled-statement bodies, and Ruby lambda / brace-block bodies. Go variadic and Python `*args` / `**kwargs` parameters are seeded with correct arity. C/C++ `scanf` / `fscanf` / `sscanf` / `read` register their output buffers as taint sources. TypeScript gated sinks dropped from the JS mirror were restored (`_.template`, `http.get` / `https.get`, `setValue` / `dotProp.set` / `jp.set`). The weak-hash and HTTP-URL AST patterns match single- and double-quoted string literals across JS, TS, and Ruby.
- **Symbolic execution.** Interprocedural parameter seeding fixed an off-by-one for method calls and now seeds the receiver / self parameter; the cross-file depth guard increments on descent; and a path cut short by the global step budget records `Inconclusive` instead of `Confirmed`.
- **Abstract interpretation and pointer analysis.** Interval division handles the `i64::MIN / -1` overflow (degrading to unbounded instead of a falsely-narrow range) and multiplication computes overflow in `i128`. `AbstractState::leq` checks entries present only in the other state, restoring a sound partial order. The pointer fixpoint re-projects container-element field reads after the receiver's points-to set converges.
- **CFG-level analyses.** Error-fallthrough termination stops at the `if` join point; a guard's constant-operand test refuses a `Source`-labelled call result; guard / sanitizer matchers require a leaf-name boundary (so `invalidate` no longer matches the `validate` guard and `unquote` no longer matches `quote`); resource ownership-transfer requires a real `->field =` assignment rather than any `->` in a span; post-dominators are computed once per resource pass; and the web-entrypoint heuristic confirms web parameters against the candidate handler only, so an unrelated `req` parameter elsewhere in the file no longer promotes batch / CLI functions to web entry points.

### Cross-file authorization

- **Caller-scope authorization lifting.** A private helper that is never itself a route handler now inherits route-level authorization from the units that call it. Pass 1 records one caller-scope edge per (caller, callee) pair; pass 2 appends synthetic route-level checks to a callee only when *every* observed caller is authorized, so one unauthorized path anywhere refuses the lift. Removes the dominant missing-ownership-check false positive on layered `services/` code without weakening the check itself.
- **Cross-file authorization on the indexed scan path.** Caller-scope edges and FastAPI router facts are persisted per file and reloaded in pass 2, so the lift applies under `--index auto` (the CLI default) and not only under `--index off`. Both fact sets previously existed in memory only, which meant a default scan of a layered project reported the ownership false positives the lift is designed to remove: on the cross-file auth fixtures, `--index auto` returned up to twice the findings of `--index off`. The loader replays persisted edges through the same fold the non-indexed path uses, and the accumulator is rebuilt from raw per-file edges on every scan rather than stored folded, because `all_authorized` is a conjunction and a stored conjunction cannot be corrected when a contributing file is edited or deleted. Indexed-vs-non-indexed parity for these fixtures is now covered by cold and warm cases in `tests/indexed_parity_tests.rs`. Requires a one-time re-index: the cache schema version moves to 5.
- **Framework fact suppliers.** Three extractors feed the mechanism without putting framework knowledge in its core: gitea-style `web.Router` closure groups (ownership middleware is recognised structurally, by a permission-field read paired with an error emit, rather than by a name allowlist), graphene `Meta.permissions` mutation classes, and FastAPI `include_router`, which is now a cycle-guarded transitive graph instead of a single-hop lookup.

### Static engine precision and recall

- **Divergent guards.** A guard whose failing branch aborts is dominating again. `LangAnalysisRules::terminators` was populated only from user config, so out of the box no language had any never-returning call at all and the aborting branch kept a fall-through edge into the join, where the `validated_must` intersection erased the guard's narrowing. PHP `die` / `exit`, C/C++ `exit` / `abort` / `err`, Rust `panic!` / `unreachable!` / `process::exit`, Python `sys.exit`, Go `os.Exit` / `log.Fatal`, Java `System.exit`, JS `process.exit`, and Ruby `exit` / `abort` are now built-in terminators, with user config unioned on top. PHP's `exit_statement` is additionally mapped as a control-flow sink, since `exit` parses as its own node rather than as a call. Restores suppression of every "validate, else abort" shape, including the dash-prefix hostname gate in the patched CVE-2017-1000117 fixture.
- **Rust match guards.** `let x = match v { g if <guard> => …, _ => return }` no longer reports `x` as unvalidated. When every arm other than the guarded one diverges, the guard-false gate is dropped from the statement frontier instead of being handed to the join as a predecessor on which the binding was never validated.
- **`execv*` executable path.** The `execv` / `execve` / `execvp` / `execvpe` gates listed only the argv vector as a payload position, on the reasoning that argument 0 is not shell-parsed. There is no shell in `execv*`, so no metacharacter is needed: attacker control of argument 0 is direct arbitrary-program execution. `execvp(getenv("PROG_PATH"), NULL)` was silent in C and C++ and now reports. The existing argv-array refinement that keeps the CVE-2017-1000117 env-config shape (`execvp(args[0], args)`) quiet now resolves an element read back to its container, so it still applies with argument 0 in scope.
- **Structural and taint engines agree on what a source is.** The structural pass treated every `Source`-labelled node as non-constant without mirroring the taint engine's network-fetch exemption, so `file_get_contents("https://api.example.com/health")` followed by `echo` reported an unguarded sink on data that provably came from a compile-time-pinned endpoint. Both engines now consult one predicate.
- **`String.valueOf(x.length())`.** Restored, in argument-aware form, the confinement that a blanket `String.valueOf` safe-string arm used to provide before it was removed as unsound. The zero-argument numeric-length accessors are classified instead of the wrapper, so `String.valueOf(rendered.length())` is confined while `String.valueOf(userInput)` still flows.
- **TypeScript typed parameters.** An id-shaped parameter carrying any type annotation was dropped from `unit.params`, and since TypeScript annotates essentially every parameter, single-parameter helpers ended up with no user-input evidence at all and could never report a missing ownership check. The drop is now gated on the annotation naming a payload-incompatible primitive (`number` / `bigint` / `boolean`), matching the Go arm, so `targetUserId: string` is user input again while `userId: number` stays a caller-passed scope key.
- **Must-leaks are security findings.** `state-resource-leak` is emitted only when a resource is acquired on every path and reaches no release call, out-parameter, or field escape; anything weaker is already downgraded to `state-resource-leak-possible` at the emit site. It is now categorised `Security` (CWE-401 / CWE-404 resource exhaustion) rather than `Reliability`. The may-analyses (`state-resource-leak-possible`, `cfg-resource-leak`, `cfg-error-fallthrough`) stay `Reliability`. Because a leak fixture's only finding is a leak, the blanket demotion had removed must-leaks from the security stream entirely: the rule fired, but every consumer filtering on `Security` saw nothing.
- **Interprocedural confinement post-conditions.** Function summaries carry five new proved properties about a callee: a boolean prefix-check the caller branches on, a throw-if-false assert guard, a `Result` rejection guard, a same-origin URL normaliser, and a `strncmp`-confined return. Each closes a false positive on the *patched* form of a real CVE whose fix introduced a custom confinement helper that name matching missed. Suppressions are capability-scoped, so a confined value reaching a SQL or command sink still fires.
- **Validation-polarity fix.** A negative-polarity validator (`isInvalidUrl`, `is_not_valid`) marked the *reject* branch as validated, exactly inverting the intended narrowing. Both branches now resolve correctly.
- **Resource ownership.** Leak, double-close, and use-after-close tracking moved from flat per-acquire tracking to an ownership model: a JDBC `Statement` whose `Connection` is body-local no longer reports, connections borrowed from a managed session (Hibernate `Session`, `EntityManager`, Liquibase `Database`) are distinguished from owned ones, and C/C++ struct-field handles are attributed to the containing object with an escape-analysis carve-out for locals that die in the same body.
- **Go multi-assign definition attribution.** `f, err := os.Open(p)` bound the handle to `err` rather than `f`. The first identifier is now the primary definition. Removes a false leak on `err`, recovers a real missed leak on the handle, and recovers taint through `val, ok := os.LookupEnv()`.
- **Explicit sink payload positions.** Sinks declare which argument positions carry the payload instead of implicitly treating all of them as payload (Rust `fs::*` / `File::*`, JS/TS raw-SQL builders, Go GORM query methods), and `promisify` aliases inherit the wrapped callee's restriction. The SSA sink scan is restricted to identifiers syntactically inside the inner sink sub-expression, so a tainted sibling field in an aggregate literal no longer implicates a constant-path `File::open`.
- **Multi-capability sink de-masking.** A helper parameter consumed at two different sink classes now emits one finding per class instead of collapsing into a single conflated rule.
- **Language coverage.** C gains twelve out-parameter propagations (`strcpy`, `strlcat`, `snprintf`, `memcpy`, `realpath` families) so path assembly through destination buffers keeps taint. Java gains Apache HttpClient request constructors as SSRF sinks; PHP gains Symfony HttpFoundation request accessors as sources; Go gains GORM query-builder SQL sinks; Ruby gains raw `pg` driver sinks with `exec_params` correctly excluded, and models `operator_assignment` as an assignment. Rust resolves `let x: T` annotations and `parse::<T>` turbofish, settling the `FromStr` ambiguity so `let p: PathBuf = s.parse()?` fires while `let port: u16 = s.parse()?` stays suppressed.
- **Corpus.** Ground truth grows from 563 to 674 cases with no existing expectation modified or removed, including 18 new real-CVE vulnerable / patched pairs across all ten languages. Two cases that shared an id with an unrelated fixture were renamed (`rs-safe-009` on `safe_match_guard.rs` to `rs-safe-013`, `py-auth-realrepo-007` on `vuln_fastapi_route_no_dependencies.py` to `py-auth-realrepo-027`) so per-case results can be keyed on the id alone. Regression floors tighten from P 0.897 / R 0.944 / F1 0.920 to 0.980 across the board: the old margins were calibrated against a 316-case corpus and were wide enough to hide a 13-case drift.
- **Hoisted-sink provenance.** The search for a callback-nested sink no longer descends a call's callee / receiver side, so a chained call cannot inherit provenance from a sink nested in its receiver's callback. In `http.get(target, cb).on('error', cb2)` the `.on` node was recording `res.send('ok')` from inside the `http.get` receiver's callback, and that unrelated `'ok'` literal then read as a constant payload and suppressed a real SSRF finding.

### Static scan throughput

Full-scan wall clock on a 492-file Go service drops from 36.2s to 26.9s (1.35x) while reporting more findings, not fewer. Each optimization ships an equivalence argument and most an equivalence test; several carry a `NYX_DISABLE_*` toggle so the previous path can be measured from the same binary.

- **Single-pass AST queries.** Per-rule tree-sitter queries are concatenated into one multi-pattern query, so classification walks the tree once instead of once per rule.
- **O(1) node text.** A file's UTF-8 is validated once per parse and node text is taken as a boundary slice, replacing a per-node revalidation proportional to the node's byte range.
- **Cheaper hashing and lookup.** `FuncKey` caches a hash of its identity, turning the engine's most-hashed type from O(len) to O(1) per lookup; label matchers gained a last-byte dispatch index replacing a linear suffix scan; SSA lowering and the symbol interner moved to a faster hash; the CFG node map became a dense positional vector.
- **Taint worklist.** Path environments and abstract state are shared copy-on-write instead of deep-cloned per worklist step, branch-condition classification is memoized, per-call confinement checks are hoisted out of bodies with no confiner summary, and a per-file function-name index replaces four linear scans per callee resolution.
- **Dense constant-propagation results.** Constant-propagation results moved from a hash map to a dense value-indexed table, removing a per-value hashed insert per body and making every consumer lookup an array index. The persisted format is unchanged.
- **Fruitless-walk elision.** Auth extraction skips whole-subtree walks that cannot produce a result for the file's language or framework, cutting the isolated Go auth pass by roughly a quarter.

### CLI

- **`nyx scan --verify`** (enabled by default in standard builds) and `--backend {auto,process,docker}` select the dynamic-verification harness. `--no-verify` skips verification for a single run without changing config.
- **`nyx scan --harden {standard,strict}`** picks the process-backend hardening profile. `standard` is no-new-privs plus a memory rlimit on Linux. `strict` layers namespace unshare, chroot to the workdir, and a default-deny seccomp filter on Linux, or wraps the harness with `sandbox-exec` on macOS.
- **Patch-validation CI mode.** `--baseline FILE` reads a previous scan's JSON (or a stripped `.nyx/baseline.json` written by `--baseline-write`) and diffs it against the current scan on `stable_hash`, emitting `New` / `Resolved` / `FlippedConfirmed` / `FlippedNotConfirmed` transitions. `--gate {no-new-confirmed,resolve-all-confirmed}` exits non-zero when the diff violates the policy so CI fails the build instead of merging an unreviewed regression. The stripped baseline carries only `stable_hash`, `dynamic_verdict`, `severity`, `path`, and `rule_id`, so persisting it between scans does not leak source.
- **Repository triage in CI.** `nyx scan` now reads the same `.nyx/triage.json` file written by `nyx serve`. Terminal triage states (`false_positive`, `accepted_risk`, `suppressed`, `fixed`) are hidden from CLI output and excluded from `--fail-on` by default, while `--show-suppressed` includes them with `triage_state` / `triage_note` metadata for JSON, SARIF, and console output.
- **`nyx scan --verify-all-confidence`** drops the Medium cutoff and re-verifies everything.
- **`nyx scan --unsafe-sandbox`** disables hardening (development only, never for CI).
- **`nyx verify-feedback <finding_id> --wrong <reason> | --right`** records a correction or confirmation for a finding's verdict in the local telemetry log.
- **`nyx scan --explain-engine`** prints the effective engine configuration and exits without scanning.
- **`nyx surface`** (described above) with `--format {text,json,dot,svg}` and `--build`.
- **`nyx repro` subcommand.** Replays dynamic repro bundles by finding id,
  spec hash, or explicit bundle path, with `--docker`, `--print-path`, and
  `--list` helpers. The CLI now matches the browser UI's reproduced command
  and uses bundle manifests to bridge stable finding ids to spec-hash cache
  directories.

### Frontend

- **Project target selector in `nyx serve`.** The sidebar now remembers scan roots, lets you switch the active target, and accepts a new project path without restarting the server. `/api/targets` backs the selector, scans can opt into a different `scan_root`, and `nyx scan` / `nyx index build` register the projects they touch so `nyx serve` can pick them up later.
- **Surface page** with ELK auto-layout and the shared node-style palette.
- **Verdict badge** on finding detail, plus a dynamic-verdict section that surfaces the verdict, the payload that triggered it, and a link to the repro bundle.
- **Scan compare** gains a dynamic-verdict diff column so two scans can be compared on what was confirmed versus what was downgraded.

### License

- **Internal license grants documentation** at `LICENSE-GRANTS.md`. Grant 1 covers Nyctos derived works. The repo stays GPL-3.0-or-later; the grants document scope of internal product licensing.

## [0.7.0] - 2026-05-11

Seven new vulnerability classes, two SSA sidecars for XML and XPath parser hardening, deeper cross-file FastAPI authorization, and roughly a thousand auth false positives closed on Go DAO helpers plus the dominant Hibernate Criteria SQL cluster. Performance work on the auth extractor, SCCP, and the global summaries map. New `nyx rules list` CLI, brand-aligned web UI, and CVE corpus growth across Python, PHP, JavaScript, and C.

### Highlights

- New caps for LDAP injection, XPath injection, header / CRLF injection, open redirect, server-side template injection, XXE, and prototype pollution, with per-language label rules across all eight supported languages.
- Cross-file FastAPI authorization: `include_router` chains and module-level `APIRouter(dependencies=[...])` lift onto every attached route, with `Security(..., scopes=[...])` recognised distinctly from `Depends(...)`.
- Type-tracked XML and XPath hardening via two SSA sidecars: parser bodies setting `secure_processing` / `processEntities: false` / `resolve_entities=False`, and `XPath` instances bound to `setXPathVariableResolver(...)`, count as safe.
- ~957 `go.auth.missing_ownership_check` findings closed on gitea-shaped DAO helpers (id-scalar precision pass), 169 of 216 openmrs `cfg-unguarded-sink` findings closed on Hibernate Criteria-API receivers, joomla and drupal `php.deser.unserialize` closed on `Serializable::unserialize($input)` magic-method bodies.
- `nyx rules list` CLI subcommand, brand-aligned `nyx serve` visual refresh, regenerated README / docs screenshots and GIFs.

### Detector classes

- New `Cap` bits and canonical rule ids: `Cap::LDAP_INJECTION` / `taint-ldap-injection`, `Cap::XPATH_INJECTION` / `taint-xpath-injection`, `Cap::HEADER_INJECTION` / `taint-header-injection`, `Cap::OPEN_REDIRECT` / `taint-open-redirect`, `Cap::SSTI` / `taint-template-injection`, `Cap::XXE` / `taint-xxe`, `Cap::PROTOTYPE_POLLUTION` / `taint-prototype-pollution`. Each ships per-language sink, sanitizer, and gated-sink rules across JS/TS, Python, Java, PHP, Go, Ruby, Rust, and C/C++. Severity, OWASP 2021 mapping, and description live in `CAP_RULE_REGISTRY` (`src/labels/mod.rs`); `cap_rule_meta()` and `rule_id_for_caps()` are the public lookups.
- `Cap` widened from `u16` to `u32` to fit the new bits, with `Evidence.sink_caps` and `RuleInfo.cap_bits` following. The serde decoder accepts any unsigned integer width, so caches written before the bump still load. SQLite schema bumped from 3 to 4 to force a rescan: older `source_caps` / `sanitizer_caps` / `sink_caps` blobs predate the new bits.
- `owasp_bucket_for` consults `CAP_RULE_REGISTRY` first, so adding a cap class no longer needs a second-table edit. The match requires an exact rule id or a recognised separator (` `, `(`, `.`), so a future `taint-ssrf-allowlist-violation` cannot inherit `taint-ssrf`'s bucket. The legacy family-token table also routes `xpath`, `header`, and `xxe` to A03 / A05.
- `issue_category_label` (dashboard badge) routes the seven new rule-id prefixes to dedicated labels: LDAP Injection, XPath Injection, Header Injection, Open Redirect, Template Injection, XXE, Prototype Pollution.

### Engine

- `src/ssa/xml_config.rs` tracks XML-parser configuration alongside type-fact analysis, carrying per-receiver `secure_processing` / `disallow_doctype` / `external_entities` flags through copy assignments and phi joins (meet for safe flags, sticky union for the unsafe `external_entities` polarity). `xxe_safe()` strips `Cap::XXE` at the type-qualified `XmlParser.parse` sink when the parser was provably hardened (JAXP `setFeature(FEATURE_SECURE_PROCESSING, true)`, lxml `XMLParser(resolve_entities=False, no_network=True)`, fast-xml-parser `processEntities: false`). Persisted to `OptimizeResult.xml_parser_config`.
- `src/ssa/xpath_config.rs` mirrors it for Java `XPath` instances: `setXPathVariableResolver(...)` flips the receiver's `has_resolver` flag, copy assignments union, phi joins meet. `xpath_safe()` strips `Cap::XPATH_INJECTION` at `xpath.evaluate(expr, ...)` / `xpath.compile(expr)` sinks when the receiver was provably bound to a resolver. Persisted to `OptimizeResult.xpath_config`.
- Five `TypeKind` variants: `LdapClient` (JNDI `InitialDirContext` / `InitialLdapContext`, Spring `LdapTemplate`, ldapjs `createClient`, python-ldap `initialize`, ldap3 `Connection`), `XPathClient` (JAXP `newXPath`, lxml `etree.XPath`, npm `xpath`), `XmlParser` (JAXP factory products `newDocumentBuilder`, `newSAXParser`, `getXMLReader`), `Template` (FreeMarker `new Template(...)` / `Configuration.getTemplate`), `NullPrototypeObject` (JS/TS values from `Object.create(null)`). Wired into `constructor_type` for return-type inference and `TypeKind::label_prefix()` for type-qualified callee resolution. `XPathClient` stays distinct from `DatabaseConnection` so a generic `pdo->query` SQL_QUERY sink cannot collide with `xpath.query`.
- `GateActivation::LiteralOnly` fires only when the activation argument is a literal matching `dangerous_values` / `dangerous_prefixes`; unknown or dynamic activation suppresses, with no conservative `ALL_ARGS_PAYLOAD` push. For shapes identifiable only by an explicit literal flag, e.g. `jQuery.extend(true, target, src)` deep-merge against Backbone's `Model.extend({proto})`.
- Two path-state predicates for inline open-redirect sanitisers. `RelativeUrlValidated` covers `x.startsWith("/")`, `x.starts_with("/")`, `x.startswith("/")`, PHP `strpos($x, "/") === 0`, and `x[0] === "/"`. `HostAllowlistValidated` covers `new URL(x).host === ALLOWED`, `urlparse(x).netloc == ALLOWED`, multi-statement `parsed.host_str() == "..."` (Rust), `parsed.Host == "..."` / `parsed.Hostname() == "..."` (Go). Both clear `Cap::OPEN_REDIRECT` only on the validated branch; non-redirect taint downstream still fires on its own caps. The Go form gates on case-sensitive capital `H`, so a lowercase `u.host == X` field comparison falls through to the generic `Comparison` predicate.
- `is_object_create_null_call` in `cfg/literals.rs` matches `Object.create(null)` plus parenthesised, awaited, and TS type-cast wrappers, tagging `CallMeta.produces_null_proto = true`. Type-fact analysis lifts the flag to `TypeKind::NullPrototypeObject` on the returned SSA value, suppressing the synthetic `__index_set__` sink flow-sensitively. Phi joins drop the tag back to `Unknown`, so a partial null-proto receiver still fires on the unsafe path.
- CFG-layer prototype-pollution suppression at the synthetic `__index_set__` sink (JS/TS, recognised by the existing `try_lower_subscript_write` lowering). Three flow-insensitive shapes elide the `Sink(PROTOTYPE_POLLUTION)` label before SSA sees the node: constant-key fold (literal key not in `__proto__` / `constructor` / `prototype`), reject pattern (sibling `if (idx === "__proto__" || ...) return / throw / break;`), allowlist pattern (ancestor `if (idx === "name" || idx === "id") { obj[idx] = v }`). Walks stop at the enclosing function, so closure-captured guards in an outer scope cannot authorise inner assignments.
- Spring MVC `return "redirect:" + tainted` recogniser (Java). `try_lower_spring_redirect_return` in `cfg/mod.rs` matches the leftmost `+`-chain rooted at a `redirect:` string literal and emits a synthetic `__spring_redirect__` Call sink with `Sink(Cap::OPEN_REDIRECT)` between the predecessors and the Return node. Concatenated identifiers from anywhere in the right-hand chain feed the node's `arg_uses[0]`, so a tainted suffix carries through OPEN_REDIRECT.
- Subscript-set form classification for header sinks. `response.headers["X-Foo"] = bar` / `headers["X-Foo"] = bar` (Ruby `element_reference`, JS/TS `subscript_expression`, Python `subscript`) had no `property` field on the LHS. `push_node` walks into the subscript's `object` and classifies its member-expression text, so `Cap::HEADER_INJECTION` fires on the bare bracket form alongside `setHeader` / `res.set` / `headers_mut.insert`.
- PHP literal extraction extended in `cfg/literals.rs`: `encapsed_string` (double-quoted) when every child is a pure-literal segment; boolean literals (`true` / `false`) for the jQuery `extend(true, ...)` `LiteralOnly` gate; leading-string `binary_expression` concat (`"Location: " . $url`, JS/TS `"Location: " + url`) so `dangerous_prefixes` matching activates on partially dynamic concatenations.
- PHP receiver-text strip in `helpers::root_receiver_text` drops the leading `$` from `variable_name` nodes, so `$smarty->fetch(...)` / `$twig->createTemplate(...)` reconstruct as `Smarty.fetch` / `Environment.createTemplate` for suffix-matcher gates.
- Gate-callee resolution hardened for member-source rewrites. Where `first_member_label` rewrites a call's `text` to a Source like `req.body`, the gate matcher reads the call's `function` / `method` / `name` field instead, so `setValue(target, req.body, ...)` matches the `setValue` proto-pollution gate. Whitespace is stripped from the function field so multi-line chains still match flat gate matchers.
- Ruby option-constant lookup in gate activation. Bare `scope_resolution` / `constant` nodes (`Nokogiri::XML::ParseOptions::NOENT`) fall back to the macro-arg extractor used by C/C++/PHP, so Nokogiri XXE gates activate on idiomatic option-flag arguments.
- PHP `unary_op_expression` negation recognition. tree-sitter-php emits `unary_op_expression` for unary `!`; CFG `detect_negation` and condition-chain decomposition now match it, so `if (!validate($x))` no longer carries `condition_negated=false` and the surviving branch is the rejection arm, not the validated one.
- PHP container kinds `declaration_list`, `interface_declaration`, `trait_declaration`, `enum_declaration`, `enum_declaration_list` mapped to `Kind::Block`, so methods inside them participate in CFG construction.
- Go variadic `parameter_declaration` named-field handling for `collect_param_names`: `name` and `type` are read directly, so type-segment identifiers no longer pollute the param-name set (`info *PackageInfo` no longer contributes `PackageInfo`).
- Empty-formals SSA lowering signal: per-parameter summary probing seeds via `BodyMeta.param_destructured_fields`, and JS/TS arrow `() => {...}` lowers with `with_params=true`, counting as "explicitly zero formals" rather than "no formals info".

### Authorization

- FastAPI cross-file `include_router` dependency tracking. `auth_analysis/router_facts.rs` captures per-file router declarations (`<router> = X(deps=[...])`) and `<parent>.include_router(<child_module>.<child_var>)` edges in pass 1, persists them into `GlobalSummaries::router_facts_by_module`, and resolves them into the active file's `AuthorizationModel::cross_file_router_deps` at pass 2 entry. Transitive lifts (grandparent to parent to child) use an iterative index walk. Module identity is the file basename without `.py`. Closes the airflow execution-API shape where a child router lives in `routes/task_instances.py` and its auth is declared on the parent in `routes/__init__.py`.
- FastAPI router-level `dependencies=[...]` propagation. Module-level `router = APIRouter(dependencies=[Security(...)])` is pre-walked once per file and merged onto every `@<router>.<verb>(...)` route attached in that file. Closes airflow execution-API routes re-using one `ti_id_router` declared at module scope.
- FastAPI `Security(callable, scopes=[...])` recognised distinctly from `Depends(callable)`. Scoped Security promotes the synthetic `AuthCheck` to `AuthCheckKind::Other` (route-level scope-checked authorization), not Login. A scope-tracking boolean threads through `expand_decorator_calls` and `extract_fastapi_dependencies`.
- Caller-scope IPA: same-file route-handler-to-helper auth lift. `apply_caller_scope_propagation` walks every non-route helper unit; if its in-file callers are non-empty AND every caller is itself an authorized route handler (route-level non-Login auth check) or already authorized by this propagation, the caller's checks lift onto the helper as synthetic `is_route_level=true` `AuthCheck`s. Iterated to a small fixpoint to cover transitive chains (route to mid_helper to leaf_helper). Refuses to authorize helpers with no in-file caller, helpers called from a mix of authorized and unauthorized callers, and helpers called only from un-lifted helpers. Cross-file lifting is not implemented. Closes the dominant FastAPI / Django / Flask shape on sentry / saleor / airflow: route authenticates via decorator or dependency, then delegates to a private helper that performs the sink.
- Go DAO-helper id-scalar precision pass. For non-route Go units, a parameter whose declared type is a bounded primitive scalar (`int64`, `uint32`, `string`, `bool`, `byte`, `rune`, `float64`, ...) and whose name is id-shaped (`id`, `*Id`, `*_id`, `*ids`) is dropped from `unit.params` before ownership-check evaluation. Real Go HTTP handlers always carry a framework-request-typed param (`*http.Request`, `*gin.Context`, `echo.Context`, `*fiber.Ctx`), and per-framework route extractors set `include_id_like_typed=true` so id-shaped path params survive on real routes. Mirrors the Python `is_python_id_like_typed_param` filter. Closes ~957 `go.auth.missing_ownership_check` findings on gitea backend DAO helpers (`func GetRunByRepoAndID(ctx, repoID, runID int64)`, `func DeleteRunner(ctx, id int64)`, the whole `models/...` layer whose ownership check sits in the calling route handler) and equivalent shapes in minio / Go ORM codebases.
- Bare-callee verb-name fallback gate: `list(...)`, `filter(...)`, `update(...)`, `create_audit_entry(...)`, `update_coding_agent_state(...)` (no receiver dot at all) no longer classify as `DbMutation` / `DbCrossTenantRead` via the loose verb-name fallback. Real ORM/DB calls carry a receiver (`User.find(id)`, `Model.objects.filter`, `repo.save(x)`); bare `list(events)` is the Python builtin and `filter(fn, xs)` is `Iterable.filter`. New `receiver_is_simple_chain(callee)` requires a non-chained receiver dot. Realtime / outbound / cache prefix dispatches still match by chain root.

### Type-aware sinks and validators

- Java JPA / Hibernate Criteria API treated as structural SQL. `TypeKind::JpaCriteriaQuery` covers `CriteriaQuery<T>`, `CriteriaUpdate<T>`, `CriteriaDelete<T>`, `Subquery<T>`, `TypedQuery<T>`. `sink_args_jpa_criteria_query_safe` clears `cfg-unguarded-sink` SQL_QUERY when any positional argument is JpaCriteriaQuery-typed; the receiver is excluded, being the Session/EntityManager channel in `session.createQuery(cq)` and never the SQL payload. `cb.createQuery(...)`, `em.getCriteriaBuilder()`, and the JpaCriteriaQuery type chain are inferred via constructor / factory return-type hints in `type_facts.rs`. Closes the dominant FP cluster on openmrs (169 of 216 cfg-unguarded-sink), xwiki, and keycloak Hibernate DAO methods.
- Receiver-side validator registry. `labels::lookup_receiver_validator(lang, callee)` clears `Cap` from the receiver value (and call equivalents) on success, unlike `Sanitizer`, which clears caps from the return value. Python registers `relative_to => Cap::FILE_IO`, so `path.relative_to(base)` drops the file-IO cap on the path. Closes the CVE-2024-23334 patched aiohttp `static_root_path.joinpath(filename).resolve().relative_to(static_root_path)` shape.
- JS/TS Array-method validator-callback narrowing. `arr.filter(isSafeIdentifier)`, `arr.find(isValidId)`, `arr.findLast(...)` with a `BooleanTrueIsValid` callback (`isValid...`, `isSafe...`, `hasValid...` and snake-case variants) propagate `validated_must` through the return value. Callback name resolves from `info.arg_callees` (call-shape arguments) and SSA `value_defs[v].var_name` (bare-identifier callbacks, the dominant patched-CVE form). Strict-additive: anonymous arrows and opaque identifiers leave existing propagation untouched. `findIndex` / `every` / `some` excluded (scalar return shape). Motivated by CVE-2026-42353.
- JS/TS ternary-branch source classification. `let arr = cond ? req.query.lng : "";` lowered each branch to a labelless Assign with empty uses, so the join phi saw no taint. `lower_ternary_branch` runs `first_member_label` on the branch AST when no `Source` label is attached.
- PHP `fopen` modeled as `Sink(Cap::SSRF)`, the same dual SSRF / LFI shape as `file_get_contents`; fires only on tainted argument. Closes CVE-2026-33486 (roadiz/documents `DownloadedFile::fromUrl` wrapping `fopen($url, 'r')`).
- PHP `Serializable::unserialize($input)` magic-method passthrough recognition. The legacy `Serializable` contract (deprecated since PHP 8.1) requires the implementation to call `\unserialize($input)` on its formal parameter inside `public function unserialize($x) { ... }`, and PHP invokes the method when restoring an instance, so the call cannot be removed without breaking the interface. `php.deser.unserialize` suppresses inside that exact shape (method named `unserialize`, single formal, bare-parameter argument). The actionable signal is the class-level `Serializable` implementation, the fix being migration to `__serialize` / `__unserialize`. Closes joomla / drupal Serializable-implementing class FPs.
- SQLAlchemy query-builder chained-call recognition. `select(X).filter_by(...)`, `query(X).filter(...)`, `select().join().where()` anchor through the chain root primitive when the chain receiver type is opaque. New `db_query_builder_roots` config (Python defaults `select`, `query`). Closes airflow `session.scalar(select(C).filter_by(conn_id=user_input))` shapes that dropped under the chained-call suppression in `classify_sink_class`.
- Python non-sink container constructor recognition. Bare-callee `set()` / `dict()` / `list()` / `tuple()` / `frozenset()` / `defaultdict(...)` counts as a non-sink constructor, so `verified_ids = set(); verified_ids.update(myteams)` does not classify the `.update` call as `DbMutation`. Type-annotation hints `set[int]` / `dict[str, int]` are recognised via PEP 585 generic suffix strip alongside the existing angle-bracket strip.
- Python `request.match_info` source label (aiohttp path-parameter source).
- New Python pattern `py.xss.make_response_format` (Tier B) for Flask `make_response(<f-string-or-concat>)` reflection, matching bare `make_response(...)` and `flask.make_response(...)`. Closes CVE-2023-6568 (mlflow auth `create_user` reflecting an attacker-controlled `Content-Type` header into the response body).

### Language coverage

Per-language label rules expanded for the seven new caps.

- **JavaScript / TypeScript:** ldapjs `LdapClient.search`, `escapeXpath` / `xpathEscape`, `document.evaluate` / npm `xpath.select`, `setHeader` / `res.set` / `res.append` / `res.headers[]=`, `stripCRLF` / `escapeHeader`, lodash / dot-prop / object-path deep-merge prototype-pollution gates, Handlebars / EJS / Mustache template sinks, fast-xml-parser / xml2js with `processEntities`-aware activation, `redirect` / `Location` open-redirect sinks.
- **Python:** python-ldap `LDAPObject.search_s`, ldap3 `Connection.search`, lxml `etree.XPath` / `lxml.etree.parse` with parser-config awareness, Flask `response.headers[]=` / `make_response`, Jinja2 `Template(...)` and Mako `Template(...)` SSTI sinks, `flask.redirect` / `aiohttp HTTPFound` open-redirect.
- **Java / Kotlin:** `DirContext.search`, `XPath.evaluate` / `XPath.compile`, JAXP `DocumentBuilder.parse` / `SAXParser.parse` / `XMLReader.parse`, FreeMarker `Template.process`, Spring `redirect:` view-name synthetic sink, `HttpServletResponse.setHeader` / `addHeader`.
- **PHP:** `ldap_search` / `ldap_list` / `ldap_read`, `DOMXPath::query` / `DOMXPath::evaluate`, `header()` with leading-prefix activation, Smarty `fetch` / Twig `createTemplate` / Blade compile + `eval` template forms, `loadXML` / `simplexml_load_string` with `LIBXML_NOENT` activation.
- **Go:** `go-ldap conn.Search`, `etree.Path` / `xmlpath.Compile`, `http.Header.Set` / `Response.Header().Set`, `html/template` and `text/template` `Parse(...)`, `encoding/xml.Unmarshal` / `Decoder.Decode`, `http.Redirect` with relative-URL / host-allowlist gating.
- **Ruby:** `Net::LDAP#search`, `Nokogiri::XML::Document#xpath`, `response.headers[]=`, `ERB.new` SSTI, `Nokogiri::XML.parse` with `NOENT` / `DTDLOAD` activation, `redirect_to` with relative-URL gate.
- **C / C++:** libldap `ldap_search_ext_s`, libxml2 `xmlXPathEval`, `curl_easy_setopt` with header-list activation, libxml2 `xmlReadFile` / `xmlReadMemory` with `XML_PARSE_NOENT` activation.
- **Rust:** actix-web `HeaderMap.insert` / `HeaderValue::from_str` header-injection gates. `Redirect::to` retagged from `Cap::SSRF` to `Cap::OPEN_REDIRECT` so the open-redirect rule fires distinctly from the SSRF rule.

`NYX_PYTHON_PROTO_POLLUTION` opt-in flag: Python `dict.update` / `__dict__.update` proto-pollution gates are off by default because bare `update` overlaps too broadly with `Counter.update` and ordinary state mutation to ship as a default sink.

### CVE corpus

- C: CVE-2017-1000117 (git argv injection via `ssh://-oProxyCommand=...`) vulnerable + patched fixtures under `tests/benchmark/cve_corpus/c/CVE-2017-1000117/`. Remaining gap: array-element taint propagation, `c.cmdi.exec*` AST patterns, dash-prefix-byte sanitizer recognition.
- Python: CVE-2023-6568 (mlflow reflected XSS), CVE-2024-21513 (langchain SQL / Jinja), CVE-2024-23334 (aiohttp static-file path traversal) vulnerable + patched fixtures.
- PHP: CVE-2026-33486 (roadiz/documents SSRF) vulnerable + patched fixtures.
- JavaScript: CVE-2026-42353 (i18next-http-middleware path traversal) vulnerable + patched fixtures.

### CLI

- `nyx rules list` surfaces the same registry the dashboard's `/api/rules` page reads: built-in cap-class entries (one per `Cap` with a canonical rule id), per-language label rules (sink / source / sanitizer), gated sinks, custom rules from config. Filters `--lang <slug>`, `--kind <class|source|sink|sanitizer>`, `--class-only` for registry entries only, `--no-class` for per-language rules only. `--json` for machine output. Cap-class entries carry `language = "all"`, so a language filter still surfaces them unless `--no-class` is set.
- New `RuleInfo.is_class` / `RuleInfo.emission_active` flags. Cap-class entries carry `is_class = true` so dashboards can group them separately. `emission_active = false` marks legacy classes (SQL_QUERY, SSRF, FILE_IO, FMT_STRING, DESERIALIZE, CODE_EXEC, CRYPTO) whose findings still surface under the catch-all `taint-unsanitised-flow` rule id; the seven new classes plus `unauthorized_id` and `data_exfil` are `emission_active = true`. `cap_rule_registry_emission_active_set_is_pinned` pins the active set so migrating a legacy cap cannot drift silently.
- `parse_cap` and `CapName::FromStr` accept the new short names: `ldap_injection` / `ldapi`, `xpath_injection` / `xpathi`, `header_injection` / `crlf` / `response_splitting`, `open_redirect` / `redirect`, `ssti` / `template_injection`, `xxe`, `prototype_pollution` / `proto_pollution`, plus the existing `data_exfil` alias. The `nyx config add-rule --cap` flag and `[analysis.languages.*.rules]` entries take any of these.

### Frontend

- Local web UI restyled around the mint-cyan Nyx brand: warmer light surfaces, deep green accents, updated severity / confidence colors, tighter typography, smaller radii, denser cards, table, badge, button, header, and sidebar styling, matched graph / code-viewer colors.
- `nyx serve` surfaces reworked for a more operational layout. Overview uses the refreshed health-score card and chart grid; Scans has a fixed compact table with capped language badges; Scan Detail places summary and timing side by side; Triage, Rules, Config, Explorer, Finding Detail, Scan Compare, and Debug got spacing, overflow, and density fixes.
- Branded asset set shared between the SPA and the embedded server bundle: PNG favicons, Apple touch icon, sidebar logo image, refreshed SVG favicon, Rust static handlers for the new `/logo.png` and favicon files.
- `RuleListItem` and `RuleDetailView` carry the new `is_class` flag so the dashboard's Rules page can group cap-class entries separately.
- README and docs screenshots and GIFs regenerated against the new UI at 1600x992, saving raw originals before framing and adding CLI GIF plus combined CLI-to-serve demo GIF capture. The capture workflow gained mint-led framing copy, optional `nyxscan.dev` asset mirroring, WebP regeneration for mirrored PNGs, raw `_raw` image / GIF outputs.

### Performance

- `collect_top_level_units` hoisted out of the per-extractor loop in `extract_authorization_model`. Multi-extractor languages (Go gin+echo, JS/TS express+koa+fastify, Python flask+django, Rust axum+actix_web+rocket, Ruby sinatra) had been re-walking the whole AST and rebuilding the `Function`-kind unit set per extractor, then deduping by span. New `AuthExtractor::requires_top_level_units()` opt-out for Spring / Rails, which build their own. Was 46% of `extract_authorization_model` wall-clock on the mattermost/server/channels/app subtree.
- Single `AuthorizationModel` build per file in fused mode. The diag path and the per-file summary path each ran their own `extract_authorization_model`, duplicating the hoisted unit pass and every framework extractor's AST walk. Auth summaries now extract from the base model (pre var-types, pre helper-lifting), so the persisted per-file summary matches the legacy `extract_auth_summaries_by_key` path bit-for-bit.
- O(N) shallow value-ref emission in `collect_unit_state`. Per-node `extract_value_refs(node, bytes)` walked the entire subtree at every recursion level (O(N²) per body) even though the recursion below already visits every descendant once. New `append_shallow_value_ref` emits the node's own ref and lets recursion handle the descent; public callers (`collect_call`, `collect_condition`, assignment-side extraction) keep the deep walk. Was ~17% + 15% + 11% of wall-clock across `build_function_unit_with_meta`, `collect_unit_state`, and `extract_value_refs` on mattermost.
- Per-`ParsedFile` `body_const_facts_cache: OnceCell`. SSA + const-prop + type-fact build was running 2-3× per body across `run_cfg_analyses_with_lowered`, `run_auth_analyses`, and `collect_file_var_types`. Single-pass cache; gin profile dropped from 13.6% to ~4.5%.
- SCCP switched from `HashMap<SsaValue, _>` and `HashSet<(BlockId, BlockId)>` to a dense `Vec` per-value lattice and per-destination predecessor `SmallVec<[BlockId; 2]>`, so the inner fixed-point loop no longer SipHashes a 64-bit pair for every operand of every phi. Public `ConstPropResult` shape unchanged (one final O(num_values) HashMap conversion).
- `GlobalSummaries.by_key` switched to `FxHashMap` (rustc-hash 2.1) from stdlib SipHash. `FuncKey` carries 3 String fields, so any HashMap operation hashes at least 30 bytes; FxHash is ~5× faster on this workload. Seed is fixed (no DoS hardening), fine for an in-process index keyed by program-derived names.
- `large_go_module.go` perf fixture (1493 lines) added to `benches/perf_fixtures/`; `benches/scan_bench.rs` extended with auth-extractor, SCCP, and summary-resolution rows.

### Fixed (false positives)

- `Object.create(null)` receivers no longer fire prototype-pollution at the synthetic `__index_set__` sink. Suppression is flow-sensitive via `TypeKind::NullPrototypeObject` so a phi join that only sometimes resolves to a null-proto receiver still fires on the unsafe path.
- `cfg-unguarded-sink` over-fires on JS/TS object-literal property writes guarded by an explicit `__proto__` / `constructor` / `prototype` reject `if` (early `return` / `throw` / `break`) or by an allowlist `if` whose true arm contains the assignment.
- Spring MVC `return "redirect:" + url` flagged generic `taint-unsanitised-flow` even when the redirect destination was the load-bearing taint. Now routed through the synthetic `__spring_redirect__` sink, so the finding emerges as `taint-open-redirect`.
- `$smarty->fetch(...)` / `$twig->createTemplate(...)` no longer drop their SSTI gate match on idiomatic PHP receiver shapes.
- `setValue(target, req.body, ...)` and similar wrappers no longer gate-match on the rewritten Source `req.body` text.
- Nokogiri / lxml / fast-xml-parser parser bodies hardened with `setFeature` / `processEntities: false` / `XMLParser(resolve_entities=False)` no longer fire `taint-xxe`.
- `XPath` instances bound to `setXPathVariableResolver(...)` no longer fire `taint-xpath-injection` on subsequent `xpath.evaluate(expr, ...)` sinks.
- Inline `if (!url.startsWith("/")) reject` and `if (new URL(url).host !== ALLOWED) reject` open-redirect sanitisers narrow `Cap::OPEN_REDIRECT` on the validated branch instead of falling through to the generic `Comparison` predicate.
- Rust `Redirect::to` no longer fires `taint-ssrf` for what is structurally an open redirect; retagged to `Cap::OPEN_REDIRECT`.
- ~957 gitea backend DAO `go.auth.missing_ownership_check` findings (id-scalar precision pass).
- 169 of 216 openmrs `cfg-unguarded-sink` findings (JpaCriteriaQuery type). Equivalent reductions on xwiki / keycloak Hibernate DAO clusters.
- joomla and drupal `php.deser.unserialize` flagged inside `Serializable::unserialize($input)` magic-method bodies.
- airflow execution-API routes flagged `missing_ownership_check` despite being authorized via cross-file `include_router` chains and module-level `APIRouter(dependencies=[...])` declarations.
- sentry `verified_ids = set(); verified_ids.update(myteams)` flagged as `DbMutation`.
- aiohttp `path.relative_to(static_root_path)` not recognised as a path-traversal validator.
- i18next-http-middleware `arr.filter(utils.isSafeIdentifier)` not narrowing taint on the result.
- `cond ? req.query.lng : ""` ternary lost `Source` label on the truthy branch.
- `if (!validate($x))` rejection-arm narrowing flipped on PHP unary `!`.
- mlflow `make_response(f"Invalid content type: '{content_type}'")` (Tier B pattern).
- Bare-callee verb-name dispatch on Python builtins / locally-defined helpers (`list`, `filter`, `update`, `create_audit_entry`, `update_coding_agent_state`).
- FastAPI `Depends(...)` / `Security(...)` deps declared on a module-level `APIRouter` no longer dropped on every attached route.
- FastAPI `Security(callable, scopes=[...])` no longer downgraded to a Login-only check.

### Tests

- New per-cap integration suites `tests/{xpath_injection,xxe,ssti,prototype_pollution,header_injection,open_redirect,ldap_injection}_tests.rs`, plus `python_proto_pollution_tests.rs` for the env-gated Python form. Per-cap fixture trees under `tests/fixtures/<class>/<lang>/` cover safe, unsafe, and irrelevant-baseline shapes for every supported language.
- Cross-file FastAPI integration test `tests/fastapi_cross_file_include_router_tests.rs` with airflow-shaped fixture tree under `tests/fixtures/auth_cross_file/airflow_execution_api_includes/`.
- New `cfg/cfg_tests.rs` covers ternary-branch CFG lowering shapes.
- New `summary/tests.rs` covers cross-file `include_router` summary persistence and resolution.
- Per-language safe / vuln auth and detector fixtures across Python, Java, Go, PHP, JS, TS.

### Other

- Refactor passes across `auth_analysis`, `ssa/const_prop`, `ssa/type_facts`, `summary`, and the per-framework auth extractors (cleaner conditional checks, simpler function signatures, deduplicated assertions). No behaviour change.
- README links to a Simplified Chinese translation (`README.zh-CN.md`).

## [0.6.1] - 2026-05-03

A precision pass on auth and resource analysis, three fresh CVE corpus pairs, and a UTF-8 slice panic in the path abstract domain. Closes ~1900 Go auth FPs on gitea-shaped helpers, the mastodon/diaspora private-callback Ruby controller pattern, and a phantom-taint outbreak from JS/TS / Java lambda shorthand in jest-style nested test callbacks.

### Added

- Java JDBC raw-SQL sinks `Statement.execute`, `Statement.executeBatch`, `Statement.executeLargeUpdate` modeled as `SQL_QUERY`, classified via type-qualified resolution (`DatabaseConnection.execute`) so bare `execute` (Runnable, Executor, HttpClient) does not over-fire. `conn.createStatement()` and `conn.prepareCall()` infer return type `DatabaseConnection`, so the JDBC chain `Statement s = conn.createStatement(); s.execute(q)` types `s` correctly. Closes GHSA-h8cj-hpmg-636v (Appsmith FilterDataServiceCE.dropTable). Vulnerable + patched Java fixtures added.
- Java/Kotlin `Pattern.matcher(value).matches()` chain recognised as a `ValidationCall` allowlist. The receiver of `.matcher(` must contain `regex` or `pattern`; the validation target is the `.matcher()` argument, not the bare `.matches()` receiver. Branch narrowing applies `validated_must` to the input variable on the surviving branch. Same GHSA as above (`FILTER_TEMP_TABLE_NAME_PATTERN.matcher(tableName).matches()`).
- Per-parameter SSA summary probe receives `BodyMeta.param_types`, so `extract_ssa_func_summary` runs a local `analyze_types_with_param_types` pass before extraction. Helper bodies whose sinks resolve only via type-qualified callees (e.g. `DatabaseConnection.execute` for JDBC `Statement.execute`) no longer drop the sink during cross-function summary extraction. Fixes the Appsmith helper `executeDbQuery(query)` routing SQL through `statement.execute(query)`.
- Short-circuit branch condition CFG nodes mirror `condition_vars` into `taint.uses`, so `apply_branch_predicates` interns the variable for short-circuit-decomposed validators (`if (x == null || !regex.matcher(x).matches()) throw`). Previously the per-disjunct cond nodes from `build_condition_chain` no-opped and `x` never reached `validated_must` on the surviving branch.
- Go `goqu.L(s)` and `goqu.Lit(s)` raw-SQL literal builders modeled as `SQL_QUERY` sinks. Safe siblings (`goqu.I` identifier, `goqu.C` column, `goqu.T` table, `goqu.V` parameterised value, `goqu.SUM`, `goqu.COUNT`, ...) stay unlabeled. Gin source list extended with the array-returning siblings of the existing scalar helpers: `c.QueryArray`, `c.GetQueryArray`, `c.PostFormArray`, `c.GetPostFormArray`. Closes CVE-2026-41422 (daptin: `c.QueryArray("column")` reaching `goqu.L(project)`, loop variable lifted through `for _, project := range columns`). Vulnerable + patched Go corpus pair under `tests/benchmark/cve_corpus/go/CVE-2026-41422/`.
- Go `for ident := range iter` def-use lifting. The `range_clause` child of `for_statement` is consulted when `left`/`right` aren't direct fields of the `for` node, so taint from the iterable reaches the loop binding. Required for the daptin CVE shape above.
- Java `enhanced_for_statement`, PHP `foreach`, and Ruby `for` def-use lifting, completing the loop forms the Go `range_clause` fix started. The `Kind::For` def-use arm only knew the JS/Python `left`/`right` pair and Go's `range_clause`; Java carries the binding on `name` and the iterable on `value`, Ruby's `for` on `pattern`/`value`, and PHP's `foreach` keeps both as unnamed children split by the `as` keyword, so none recorded the loop variable as a define and taint on the iterable never reached the binding (`for (Cookie c : req.getCookies()) { ... c.getValue() ... }` lost the flow at `c`). Each form folds onto the shared define/use path. Lifts Java OWASP Benchmark recall: path_traversal 0.21 to 0.32, sqli 0.16 to 0.28, cmdi 0.04 to 0.08.
- Iterable-expression classification for the loop forms above: the loop node is classified against its iterable text, so a source-returning iterable (`req.getCookies()`, `req.getParameterValues("v")`, `$_GET['list']`) lands a `Source` on the loop node and the binding inherits its taint, the same rewrite JS/Python `for ... of` / `for ... in` already had. Subscript iterables (`$_GET['x']`, `params[:list]`) classify on their base object, since sources key on the base name, not the index.
- Java iterable-returning request accessors modeled as sources: `getParameterValues`, `getParameterMap`, `getParameterNames`, `getHeaders`, `getHeaderNames`. The `getParameter` / `getHeader` matchers are word-boundary suffix matches and never covered the plural collection variants feeding for-each loops (`for (String s : req.getParameterValues("v"))`), the dominant OWASP Benchmark vulnerable-source shape.
- Rust format-string named-argument lifting (`format!("...{x}...")`, stable since 1.58). Identifiers captured by `{name}` / `{name:fmt-spec}` are pulled into the call's `uses` for known format-style macros: `format`, `print`/`println`, `eprint`/`eprintln`, `write`/`writeln`, `panic`, `format_args`, `assert`/`debug_assert`, `todo`, `unimplemented`, `unreachable`, plus log-crate severity macros (`info`, `warn`, `error`, `debug`, `trace`). Recursive descent through one or two layers of expression wrapping (`format!("{x}").to_owned()`, RHS chained method calls). Previously taint stopped at the macro boundary: `let q = format!("...{x}...")` carried no `x` because the identifier lives in format-string bytes rather than a separate AST argument node. Mirrors the Python f-string lifter.
- Rust CVE corpus extended with CVE-2023-42456, CVE-2024-32884, CVE-2025-53549 vulnerable + patched fixtures under `tests/benchmark/cve_corpus/rust/`.
- Java lambda shorthand recognised by `extract_param_meta`. `lambda_expression`'s `parameters` field as a bare `identifier` (`cmd -> ...`) or as an `inferred_parameters` wrapper around identifiers (`(a, b) -> ...`) did not match the formal_parameter / spread_parameter kinds in `PARAM_CONFIG`, so the lambda appeared parameterless and the SSA pipeline treated its formals as closure captures. Mirrors the JS/TS arrow shorthand path.

### Fixed

- Panic on non-ASCII input to `has_first_char_absolute_check` in the path abstract domain. The 32-byte search window around `[0]` was sliced as `&clause[lo..hi]` (str), which panicked when `hi` landed inside a multi-byte UTF-8 char (e.g. the em dash `—`, bytes 34..37). Switched to `&bytes[lo..hi]` with `windows()` byte-pattern checks; all needles are ASCII so the searches are equivalent. Surfaced by `cargo fuzz` (`scan_bytes` target, `.c` extension path, embedded `—` in a comment near `s[0] == '/'`). Regression test added.

### Fixed (false positives)

- `cfg-unguarded-sink` parameter-only trace no longer clears a sink argument whose reaching definition is a loop binding. Once the loop variable resolves to its iterable (the def-use lifting above), a `foreach ($param as $v) { sink($v) }` element looked like a bare `sink($p)` wrapper pass-through and the structural finding was dropped. A loop element over a parameter collection is not wrapper plumbing, so the finding survives for loop-bound sink arguments; literal-keyed arrays stay suppressed through `sink_arg_uses_safe_foreach_key`, keeping the negative case in `fp_guard_php_foreach_safe_literal_keys` firing.
- Go `unit_has_user_input_evidence` framework-request-name allow-list narrowed for Go. `ctx`, `context`, `info`, `body`, `path`, `payload`, `dto`, `form`, `query` are no longer user-input indicators on Go: there they are `context.Context` (stdlib cancellation/value-bag) or struct-pointer payload params (`info *PackageInfo`, `opts *FooOptions`), not request bindings. Go HTTP frameworks bind the request to per-framework typed params (`r *http.Request`, `c *gin.Context`, `c echo.Context`, `c *fiber.Ctx`), which arrive at the gate via `RouteHandler` kind or the type-aware param filter below. Stdlib `req` / `request` (the `*http.Request` convention) preserved. Other languages keep the broader allow-list.
- Go param collection drops `ctx context.Context` and `ctx context.CancelFunc` parameters entirely rather than seeding their names into `unit.params`. Tree-sitter-go's `parameter_declaration` exposes `name` and `type` as named fields; descend only into `name` so type-segment identifiers don't pollute the param-name set (`info *PackageInfo` no longer contributes `PackageInfo`). With the allow-list narrowing above, closes ~1900 `go.auth.missing_ownership_check` findings on gitea backend helpers whose only "user-input evidence" was the ubiquitous `ctx context.Context` first param.
- Ruby controller method visibility + filter-callback gate. Methods marked `private` (bare `private` directive, targeted `private :foo, :bar`, or `protected`) and Rails filter callback targets (`before_action`, `after_action`, `around_action`, their `prepend_*` / `append_*` / `skip_*` siblings, and the legacy `*_filter` aliases) are no longer emitted as `Function` units. Visibility tracking is class-body source-order with two directive forms (bare toggles default visibility, targeted explicitly marks named methods). Block-form filters (`before_action do ... end`) carry no symbol arg and are ignored. Closes the mastodon / diaspora `rb.auth.missing_ownership_check` flood on `set_X` row-fetch helpers used as `before_action` callbacks.
- Field-LHS resource acquires no longer counted as local resource leaks at the `apply_assignment` site. `e->name = (char *)e + sizeof(*e)` (sub-buffer alias inside a returned struct) and `mem->buf = ptr` (local-into-field ownership transfer) mark the RHS local `MOVED` and stop tracking the field as a separately OPEN resource; the parent struct owns the field's lifecycle. Cross-language, distinct from the Go-only `apply_call` field-LHS gate, which is restricted because JS/TS class-field acquires `this.fd = fs.openSync(...)` are the documented expected leak pattern in that path. Closes curl `entry_new` and equivalent C/C++ shapes in openssl / postgres.
- Empty-formals SSA lowering signal. `lower_to_ssa_with_params` sets `with_params=true` even when `formal_params` is empty, so an arrow `() => {...}` counts as "explicitly zero formals" rather than "no formals info". External vars in a zero-formal arrow are tagged as synthetic closure captures, so the JS/TS / Java auto-seed pass cannot mistake a bubbled-up free var (e.g. `userId` lifted from a nested jest test callback) for a real handler formal. Closes 934 phantom taint findings on the outline test suite (`describe("...", () => { test("...", () => { server.post(...) }) })`-shaped fixtures).
- Rust integer-typed values suppress `Cap::FILE_IO` at the abstract-domain leaf gate (previously HTML_ESCAPE only). An integer's decimal representation is digits with optional leading `-`, never path metacharacters (`/`, `\`, `.`); magnitude is irrelevant. Closes the sudo-rs RUSTSEC-2023-0069 patched FP `let uid: u32 = user.parse()?; path.push(uid.to_string())`.

## [0.6.0] - 2026-05-02

Data exfiltration splits off from SSRF, with sinks for outbound HTTP request bodies across all 10 languages and calibration tuned so plain user input echoed back upstream does not fire.

### Added

- New `taint-data-exfiltration` rule, separate from SSRF. Fires when a Sensitive-tier source (cookie, header, env, file, database, caught exception) reaches the body, headers, or json payload of an outbound HTTP call. Plain user input is suppressed at emission time, so a gateway echoing `req.body` back upstream is not flagged.
- Sinks ship for `fetch` body, `XMLHttpRequest.send`, Python `requests.post` and `httpx.AsyncClient.post`, Java JDK `HttpClient.send` with `BodyPublishers`, OkHttp builder chains, Apache HttpClient `execute`, RestTemplate, WebClient, Go `http.Post` and `http.NewRequest` + `Do`, Rust `reqwest`/`ureq`/`surf`/`hyper` body/json/form/multipart chains, Ruby `Net::HTTP.post` and RestClient, C and C++ `curl_easy_setopt(CURLOPT_POSTFIELDS, ...)` gated by the macro arg.
- Three suppression knobs:
  - Sanitizer convention. `logEvent`, `forwardPayload`, `tracker.send`, `analytics.track`, `metrics.report`, `serializeForUpstream` count as `Sanitizer(data_exfil)` by default. Add your own with the standard custom-rule path.
  - Trusted destination allowlist in `detectors.data_exfil.trusted_destinations`, matched against the abstract-string domain prefix; a literal or template prefix beginning with one of these entries drops the cap.
  - Detector toggle `detectors.data_exfil.enabled = false` strips the cap before emission. Other taint classes are unaffected.
- Calibration. Severity is High for cookie or env sources, Medium for header, file, database, or caught-exception sources. Confidence stays at Medium even with strong corroboration, drops to Low without abstract or symbolic backing, and drops one tier on path-validated flows. SARIF output carries a `properties.data_exfil_field` entry on data-exfil findings, set to the destination object-literal field the leak reached (`body`, `headers`, or `json`).
- Benchmark coverage: 13 vulnerable fixtures across 8 languages under `tests/benchmark/corpus/{lang}/data_exfil/` and 6 paired safe fixtures for the sensitivity gate and sanitizer convention. New `data_exfil` row in the per-class breakdown. Per-class CI floor at P, R, F1 ≥ 0.85 (current baseline is 1.000).
- Backwards taint walk recognises `Cap::DATA_EXFIL` and emits the same rule ID.
- Ruby SSRF coverage: `OpenURI.open_uri` classified as a sink (the low-level fetcher `URI.open` delegates to). Closes the CarrierWave CVE-2021-21288 download path and equivalent gem shapes routing through `OpenURI` directly.
- Ruby chained-call wrapper classification: statement-level wrappers like `YAML.safe_load(File.read(filename))` and `Marshal.load(File.read(p))` classify the inner sink for cross-function summary extraction. Previously the outer call became a non-sink node and the inner sink was lost when the helper was summarised.
- Ruby CVE corpus: vulnerable + patched fixtures for CVE-2021-21288 (CarrierWave SSRF) and CVE-2023-38337 (rswag path traversal).
- Lodash `_.template` modeled as a gated `Cap::CODE_EXEC` sink. Activates on the template-string argument; suppresses when arg-1 carries a literal `{ evaluate: false }`. Closes Strapi CVE-2023-22621 (server-side template injection to RCE via `<% ... %>` evaluate blocks). Vulnerable + patched fixtures added under `tests/benchmark/cve_corpus/javascript/CVE-2023-22621/`.
- JS/TS gated-sink kwarg extractor falls back to inspecting arg-1 object literals (`fn(x, { evaluate: false })`) when the language has no `keyword_argument` node, so the lodash gate can read its options object.
- Lodash double-call form (`_.template(t)(data)`) routes through `find_chained_inner_call` so the outer call's gated-sink rebinding fires.
- Cross-function helper-validation propagation. New `SsaFuncSummary.validated_params_to_return` field records parameter indices whose taint flow to the return value is fully validated by a dominating predicate (regex allowlist, type check, validation call) on every return path. At call sites, each tainted argument passed to a validated position, and the call's own return value, are marked `validated_must` / `validated_may` in the caller's SSA taint state, as an inline `if (!regex.test(x)) throw` would. Closes the helper-validator gap behind PayloadCMS CVE-2026-25544 (Drizzle SQL injection in `sanitizeValue`). Vulnerable + patched TypeScript fixtures added.
- Destructured-arg sibling expansion in per-parameter taint summary probing. JS/TS object-pattern formals (`({ column, operator, value }) => ...`) seed every binding sharing the slot, and any sibling reaching `validated_must` counts as the slot being validated. New `BodyMeta.param_destructured_fields` carries sibling lists alongside `params` and `param_types`. JS `PARAM_CONFIG` accepts `assignment_pattern` (default-value formals) and `object_pattern` (destructured formals).
- Regex-allowlist branch narrowing. `<X>.test(value)` / `<X>.match(value)` / `<X>.matches(value)` where the receiver name contains `regex` or `pattern` classifies as a `ValidationCall` and narrows the call's first argument, not the regex receiver. Also extended to `extract_validation_target` so the surviving branch validates `value`, not the regex object. Motivated by Payload CVE-2026-25544 (`if (!SAFE_STRING_REGEX.test(value)) throw ...`).
- TypeScript template-substring (`${fn(arg)}`) call-resolution arity-hint fallback. When CFG lowering drops `arg_uses` but `args` is non-empty, the resolver passes `None` so the unique-name fallback can still pick up the lone candidate.
- Caller-scope-entity exemption in `rs.auth.missing_ownership_check`. `<entity>.id` / `<entity>.pk` no longer fires when `<entity>` is a unit parameter named after a multi-tenant scope primitive: `organization` / `org`, `project`, `team`, `workspace`, `tenant`, `account`, `community`, `group`, `repository` / `repo`, `company`. Other field names (`.name`, `.slug`) still flag, and `user` / `member` / `actor` are deliberately excluded (handled by `is_actor_context_subject`). Closes a flood of FPs in Sentry / Saleor / Discourse / Mastodon-shaped multi-tenant helpers (`get_environments(request, organization)`, `_filter_releases_by_query(qs, organization, ...)`).
- Auth value-ref walker recurses into the `value` child of `keyword_argument` / `keyword_arg` / `named_argument` nodes, so `Model.objects.filter(organization_id=org.id)` no longer surfaces the kwarg key (`organization_id`) as a bare-identifier user-input subject. The schema column name is fixed at call time.
- Test-decorator denylist for Flask route extraction. `mock.patch`, `mock.patch.object` / `.dict` / `.multiple`, `unittest.mock.*`, `monkeypatch.setattr` / `setenv` / `delattr` / `delenv`, and `pytest.mark.parametrize` no longer collide with `<app>.patch` route registration. Stops every `@mock.patch("...")`-decorated test method from being attached as a Flask PATCH handler and flagged as `missing_ownership_check`.
- Typed-extractor route-level guard injection for axum and actix-web. Handlers registered via attribute macros (`#[get("/path")]`, `#[routes::path(...)]`) or external service-config builders never had their typed-extractor guards seeded. New `apply_typed_extractor_guards_to_units` walks every `Function`-kind unit and injects guard checks from typed-extractor params, complementing the route-walk path that already covered `.route(...)` registration.
- New auth config key `policy_guard_names`. Typed-extractor wrappers proving route-level capability/policy enforcement (e.g. meilisearch's `GuardedData<ActionPolicy<X>, _>`) are recognised distinctly from authentication-only wrappers. Matched as last-segment + case-insensitive `starts_with`. Rust default: `["Guarded"]`. Distinct from `login_guard_names` so the pattern doesn't pollute regular call recognition (a function like `guarded_load(..)` is not a login guard).
- Outer-wrapper-aware classification of typed extractors. `GuardedData<ActionPolicy<X>, Data<AuthController>>` is classified by the outer `GuardedData` (policy-bearing, so `AuthCheckKind::Other`), not by whether an inner generic arg substring-matches `auth`. Bare data-only extractors (`Path<u64>`, `Query<X>`, `Json<X>`, `Form<X>`, `State<X>`, `Extension<X>`, `Data<X>`) outer-name-match early-return to `None` regardless of inner type tokens. Reference-marker (`&`, `&mut`, `&'a`) and module-path (`std::collections::`) prefixes stripped before matching.
- Project-level web-framework signal in Rust auth analysis. `FrameworkContext::lang_has_web_framework(lang)` is three-valued: `Some(true)` when the manifest names a framework, `Some(false)` when it was inspected and named none, `None` when no manifest was inspected. `rust_file_imports_web_framework` probes the 8 KB file head for `axum::` / `actix_web::` / `rocket::` / `axum_extra::` imports. When Cargo.toml was inspected and lists no Rust web framework AND the file imports none, the `context_inputs` and param-name-heuristic arms of `unit_has_user_input_evidence` are suppressed; `RouteHandler` classification (concrete route-registration evidence) still bypasses the gate. Closes `missing_ownership_check` FPs in non-web Rust crates such as zed-style desktop / GUI codebases where a debug-session handle named `session` trips `matches_session_context` on `session.update(cx, ...)`. Rust-only; other languages keep prior behavior (`None`).
- Rust auth corpus extended with `safe_actix_guarded_data_extractor.rs` and `unsafe_actix_no_guarded_data_extractor.rs` (typed-extractor guard injection); `safe_non_web_rust_project/` and `unsafe_actix_web_project_no_check/` (full Cargo.toml + src/lib.rs project shapes for the framework-signal gate).
- Python auth corpus extended with `vuln_user_id_param_no_auth.py`, `safe_django_orm_caller_scoped_entity.py` (caller-scope-entity exemption), `safe_mock_patch_test_method.py` (test-decorator denylist).
- Go safe corpus extended with `safe_inner_call_close_in_arg.go` (`require.NoError(t, f.Close())` shape), `safe_struct_field_resource_owned_by_struct.go` (field-LHS ownership transfer), and a `vuln_resource_leak_no_close.go` regression guard.

### Fixed (false positives)

- C++ `cpp.memory.reinterpret_cast` no longer fires when the target type is well-defined by C++ aliasing rules. Suppressed targets: byte-pointer family (`char*`, `unsigned char*`, `signed char*`, `wchar_t*`, `uint8_t*`, `int8_t*`, `std::byte*`, `byte*`), `void*`, integer round-trip (`uintptr_t`, `intptr_t`, and `std::` variants, no pointer required), and the BSD socket address family (`sockaddr*`, `struct sockaddr*`, `sockaddr_in*`, `sockaddr_in6*`, `sockaddr_un*`, `sockaddr_storage*`). User-defined struct or class pointer targets keep firing. Closes ~70% over-fire on serialization, hashing, IPC, and socket-API code where the cast is the standard-blessed idiom.
- PHP `php.crypto.md5` and `php.crypto.sha1` suppress when the call's consuming context yields a non-cryptographic identifier name. Recognised contexts: assignment LHS (variable, `$obj->property`, `$arr['key']`), array element keys, subscript indices, return statements (resolved to the enclosing method or function name with `get` prefix stripped), and method-call arguments where the method is a key/cache/lookup verb (`get`, `set`, `has`, `delete`, `fetch`, `store`, `find`, `getItem`, `setItem`). Names containing a crypto keyword (`password`, `secret`, `token`, `signature`, `hmac`, `digest`, `salt`, `key`) keep firing. Closes ETag generation, cache-key hashing, dedup fingerprint, and `getCacheKey()`-style false positives in real PHP repos (phpmyadmin, nextcloud).
- JS and TS `secrets.fallback_secret` no longer fire on empty-string fallbacks (`process.env.X || ""`). Developers write `|| ""` to satisfy non-undefined string types without committing a real secret. Non-empty literal fallbacks still fire.
- Path-traversal sink suppression accepts canonicalised-and-rooted shapes. New `PathFact::is_path_traversal_safe` predicate clears `Cap::FILE_IO` when the path is dotdot-free and either non-absolute or carrying a verified prefix-lock. New `OPAQUE_PREFIX_LOCK` marker records the structural invariant ("rooted under SOME prefix") when the `starts_with`-style guard's argument is a method call, field access, or configured root rather than a string literal. Closes the Ruby `File.expand_path + start_with?(root)` shape (rswag CVE-2023-38337 patched counterpart), the Python `os.path.realpath + .startswith(root)` shape, and the JS `path.resolve + .startsWith(root)` shape. `classify_path_assertion` extended to JS `.startsWith(...)`, Python `.startswith(...)`, Ruby `.start_with?(...)` (paren and paren-less), and Go `strings.HasPrefix(...)`.
- Branch narrowing flips prefix-lock attachment under condition negation. For `if !target.startsWith(ROOT) { return; }` the lock attaches to the surviving block, not the rejection arm. Rejection-axis narrowing is unchanged because the rejection classifier is text-level and already accounts for leading `!`.
- Go field-LHS resource acquires no longer counted as local resource leaks. `b.cpuprof = os.Create(...)` transfers ownership to the containing struct; closure responsibility belongs to a paired `Stop()` / `Release()` method on the struct's lifecycle. Gated in both `state/transfer.rs::apply_call` and `cfg_analysis/resources.rs::run`, restricted to Go (`Lang::Go` check). JS/TS class-field acquires (`this.fd = fs.openSync(...)`) keep being tracked because the leak fixtures rely on it. Production trigger: prometheus `cmd/promtool/tsdb.go::startProfiling` cluster (`b.cpuprof`, `b.memprof`, `b.blockprof`, `b.mtxprof`).
- Go inner-call release in argument position: `require.NoError(t, f.Close())`, `errs = append(errs, f.Close())`, JUnit `assertEquals(0, in.read())` mark the receiver `CLOSED`. Bare-receiver inner calls only (chained-receiver releases stay owned by `chain_proxies`); marks `CLOSED` only with no `DoubleClose` attribution; respects `in_defer` for symmetry.

### Other

- Action download script warning for the mutable `latest` tag now references `v0.6.0` instead of `v0.5.0`.

## [0.5.0] - 2026-04-29

The biggest release since launch. The taint engine was rebuilt on top of an SSA IR, cross-file analysis was deepened across the board, and Nyx now ships a local web UI for triaging findings without leaving your machine.

> Heads-up: false positives or regressions on cross-file flows are possible. Please open an issue with a minimal reproduction if you hit one.

### Highlights

- New SSA-based taint engine: block-level worklist analysis over a pruned SSA IR, replacing the legacy BFS engine across all 10 languages. More precise, easier to extend, and the foundation for everything else in this release.
- Cross-file analysis: function summaries (including the new SSA summaries) flow across files via SQLite-backed persistence. Callee bodies can be inlined for context-sensitive analysis (k=1) and walked symbolically across file boundaries.
- Symbolic execution layer: candidate findings are walked symbolically from source to sink, producing concrete attack witnesses, pruning infeasible paths, and optionally handing constraints off to Z3.
- Local web UI (`nyx serve`): React + Vite frontend for browsing findings, viewing flow paths, and triaging results. Triage decisions persist to `.nyx/triage.json` so they version with your code.
- Hostile-repo hardening: path containment, loopback-only serving, CSRF tokens, bounded artifact reads. Safe to run on untrusted code.
- Tighter false-positive controls: type-aware sink suppression, abstract interpretation (intervals + string prefixes), constraint solving, allowlist and type-check guard recognition, confidence scoring on every finding.

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
- Validation err-check narrowing for the two-statement Go idiom `_, err := strconv.Atoi(input); if err != nil { return }`: `input` is marked validated on the surviving `err == nil` branch.
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
- Auth analysis: receiver-type sink gating, row-level ownership-equality detection, self-actor recognition (`let user = require_auth()`), sink classification (in-memory vs realtime vs outbound), helper-summary lifting, SQL JOIN-through-ACL recognition.
- State analysis (resource lifecycle, use-after-close, leaks, unauthed access) is now on by default. RAII-aware for Rust and C++; recognizes Python `with`, Go `defer`, Java try-with-resources.
- Framework rule packs: Express, Flask/Django, Spring/JNDI, Rails. Per-language label depth expanded.
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
- Scan progress reports explicit stages, timing breakdowns, language counters, skipped/reused file counts.
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
- Triage UI with database-backed decisions (true positive, false positive, accepted risk, suppressed) and `.nyx/triage.json` round-trip.
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

- Attack-surface ranking: every finding gets an exploitability score combining severity, analysis kind, evidence strength, and path-validation. Console output shows the score in the header line; `--no-rank` opts out.
- Low-noise prioritization: Quality-category findings are excluded by default (`--include-quality` brings them back). High-frequency Quality rules are rolled up per `(file, rule)` with example occurrences. LOW budgets cap noise without ever displacing High/Medium findings.
- State-model dataflow analysis: per-variable resource-lifecycle and auth-level analysis catches use-after-close, double-close, must-leak, may-leak (branch-aware), and unauthenticated-sink access. Opt-in via `scanner.enable_state_analysis`.
- Inline `nyx:ignore` suppressions with same-line and next-line directives, comma lists, wildcard suffixes, and string-literal guards across all 10 languages.
- AST pattern overhaul: all 10 language pattern files rewritten with consistent metadata, namespaced IDs (`<lang>.<category>.<specific>`), and 30+ new patterns. 11 broken tree-sitter queries fixed.
- Monotone forward-dataflow taint engine replaces the BFS engine with a worklist over a finite lattice. Termination is guaranteed by lattice height, eliminating BFS-budget bailouts on large files.
- Path-sensitive taint analysis: branch predicates flow with the analysis. Contradictory guards prune infeasible paths; validation calls produce annotated findings without changing severity.
- Interprocedural call graph: whole-program graph with three-valued callee resolution (`Resolved`/`NotFound`/`Ambiguous`), SCC analysis, and topo ordering ready for bottom-up taint propagation.

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

- Configurable analysis rules: sources, sanitizers, sinks, terminators, and event handlers can be defined per language in `nyx.local` or via `nyx config add-rule`/`add-terminator`. Config rules take priority over built-in rules.
- `nyx config` CLI subcommand with `show`, `path`, `add-rule`, `add-terminator`.
- SARIF 2.1.0 output (`-f sarif`), spec-compliant for GitHub Code Scanning, Azure DevOps, and other SARIF consumers.
- `SourceKind` taint classification: findings carry an inferred source kind (`UserInput`, `EnvironmentConfig`, `FileSystem`, `Database`, `Unknown`) and severity is derived from it instead of being hardcoded to High.
- Non-prod severity downgrade by default. Findings in tests, vendor, benchmarks, examples, fixtures, build scripts, and `*.min.js` are downgraded one tier. `--include-nonprod` restores original severity.
- Resource leak detection for Python, Ruby, PHP, JavaScript, and TypeScript (file handles, sockets, locks, mysqli, curl, fs streams).
- Progress bars and quiet mode: Indicatif-driven progress for discovery, Pass 1, and Pass 2 (auto-hidden in JSON/SARIF/quiet modes).

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

- Two-pass cross-file taint analysis. Pass 1 extracts `FuncSummary` per function (caps, propagation, callees), Pass 2 runs BFS taint propagation with cross-file callee resolution.
- CFG analysis engine with five detectors: unguarded sinks, auth gaps in web handlers, unreachable security code, error fallthrough, resource leaks.
- Cross-language interop via explicit `InteropEdge` structs (no false-positive name collisions).
- Function summaries persisted to SQLite (`function_summaries` table).
- Multi-language CFG + taint support for all 10 languages.
- Resource leak detection for C/C++, Go, Rust, and Java.
- Finding scoring system combining severity, entry-point proximity, path complexity, taint confirmation, and confidence.
- Analysis modes: `Full` (default), `Ast` (`--ast-only`), `Taint` (`--cfg-only`).
- Cap bitflags expanded: `ENV_VAR`, `HTML_ESCAPE`, `SHELL_ESCAPE`, `URL_ENCODE`, `JSON_PARSE`, `FILE_IO`.
- Performance: read-once/hash-once via `_from_bytes` variants, lock-free rayon, SQLite WAL + 8 MB cache + 256 MB mmap.
- Tracing instrumentation on all pipeline stages; criterion benchmark suite.

## [0.2.0-alpha] - 2025-06-28

- Experimental intra-procedural CFG + taint analysis for Rust. Builds a CFG, applies dataflow, and flags unsanitised Source to Sink paths (e.g. `env::var` to `Command::new`).
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
