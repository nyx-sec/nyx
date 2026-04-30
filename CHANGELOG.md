# Changelog

All notable changes to Nyx are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For where Nyx is going, see the [Roadmap](ROADMAP.md).

## [Unreleased]

### Added

- New `taint-data-exfiltration` rule, separate from SSRF. Fires when a Sensitive-tier source (cookie, header, env, file, database, caught exception) reaches the body, headers, or json payload of an outbound HTTP call. Plain user input gets suppressed at emission time so a gateway echoing `req.body` back upstream is not flagged.
- Sinks ship for `fetch` body, `XMLHttpRequest.send`, Python `requests.post` and `httpx.AsyncClient.post`, Java JDK `HttpClient.send` with `BodyPublishers`, OkHttp builder chains, Apache HttpClient `execute`, RestTemplate, WebClient, Go `http.Post` and `http.NewRequest` + `Do`, Rust `reqwest`/`ureq`/`surf`/`hyper` body/json/form/multipart chains, Ruby `Net::HTTP.post` and RestClient, C and C++ `curl_easy_setopt(CURLOPT_POSTFIELDS, ...)` gated by the macro arg.
- Three suppression knobs:
  - Sanitizer convention. `logEvent`, `forwardPayload`, `tracker.send`, `analytics.track`, `metrics.report`, `serializeForUpstream` are treated as `Sanitizer(data_exfil)` by default. Add your own with the standard custom-rule path.
  - Trusted destination allowlist in `[detectors.data_exfil].trusted_destinations`. Matched against the abstract-string domain prefix; a literal or template prefix that begins with one of these entries drops the cap.
  - Detector toggle in `[detectors.data_exfil].enabled = false` strips the cap before emission. Other taint classes are unaffected.
- Calibration. Severity is High for cookie or env sources, Medium for header, file, database, or caught-exception sources. Confidence stays at Medium even with strong corroboration, drops to Low without abstract or symbolic backing, and drops one tier on path-validated flows. SARIF output carries a `destination` field on data-exfil findings.
- Benchmark coverage. 13 vulnerable fixtures across 8 languages under `tests/benchmark/corpus/{lang}/data_exfil/` and 6 paired safe fixtures for the sensitivity gate and sanitizer convention. New `data_exfil` row in the per-class breakdown. Per-class CI floor at P, R, F1 ≥ 0.85 (current baseline is 1.000).
- Backwards taint walk recognises `Cap::DATA_EXFIL` and emits the same rule ID.

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
