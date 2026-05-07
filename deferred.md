# Deferred work

Tracking artifact for pitboss runner. Items here are work the current phase
implied or surfaced but did not finish.

## Deferred items

- [ ] Reconcile baseline location with phase 01 plan. Phase 01 deliverable
      named `.pitboss/play/recall_baseline.json`, but pitboss hard rule 2
      forbids implementer agents from writing under `.pitboss/`. Phase 01
      relocated the artifact to `tests/recall_gaps_baseline.json` (committed,
      next to the harness). If a future phase needs the baseline mirrored
      back into `.pitboss/play/`, the runner — not an implementer — must
      copy it.
- [ ] Capture a per-rule corpus snapshot (not just top-15) once phase 02
      lands so phases 03–11 can prove rule-level non-regression rather than
      aggregate-only. Out of scope for phase 01 because no engine code
      changed and the aggregate suffices for skeleton non-regression.
- [ ] Tighten `ExpectedFinding.sink_line` placeholders. Phase 01 wrote `0`
      for every gap-area test because the fixtures do not exist yet. The
      phase that un-ignores each test must update its `sink_line` (and,
      where stable, `source_line`) to a real fixture line. Phase 03 did
      this for `promise_then_callback`, `promise_all_taint`, and
      `for_await_of_stream`; phases 04–08 still own their own.
- [ ] Chained-receiver Promise shape: `Promise.resolve(req.body).then(cb)`
      and `Promise.all([...]).then(cb)` collapse in CFG (the outer `.then`
      call's text is rewritten to the inner call_expression text), so the
      SSA layer never sees a separate Call op for `.then`. Phase 03 ships
      the named-promise form (`const p = Promise.resolve(x); p.then(cb);`)
      via `try_apply_promise_callback`; the chained-receiver form needs a
      CFG-level fix that emits the outer `.then` as its own node before
      `try_apply_promise_callback` can fire on it. Out of scope for phase
      03 because the CFG rewrite is a cross-cutting change with corpus
      risk.
- [ ] `Promise.all` per-element precision. Phase 03 conservatively unions
      all element taints into a scalar `VarTaint` on the result. Real
      shape is a tuple/array where each index has its own taint; the
      array-element lattice on `VarTaint` would preserve precision so
      destructuring `Promise.all([safe, tainted]).then(([a, b]) => ...)`
      taints only `b`. Park here because a tuple lattice extension is a
      domain-wide change touching every transfer arm.
- [ ] Promise-callback finding attribution. The `.then(cb)` flow currently
      surfaces as a `taint-unsanitised-flow` finding at the `.then(cb)`
      call site (via the engine's existing source-to-callback /
      param-to-sink pairing), and a separate `cfg-unguarded-sink` finding
      still fires at the actual `db.query(data)` line inside `cb`. The
      taint trace's location should attribute to the inner sink site so a
      reviewer reading the diagnostic lands at the dangerous line, not at
      the outer call. Park because this is a reporting-layer change that
      touches every callback-pattern emitter (not just promise callbacks).
- [ ] Phase 03 audit — `tests/fixtures/realistic/async_await/handler.ts`
      was added (TS counterpart to phase 02's `handler.js`) but no
      `recall_gaps` test asserts a finding against it; only the
      pre-existing `async_await` test fires, and it pins to
      `handler.js`. The .ts file is scanned implicitly via
      `scan_fixture("async_await")` (smoke), but a positive assertion
      exercising the TS `await_expression` KINDS-map entry is still
      missing. Decide: add the assert or drop the fixture.
- [ ] Phase 03 audit — `src/cfg/mod.rs` for_in_statement text rewrite
      applies to *all* JS/TS `for_in_statement` nodes (i.e. every
      `for...of`, `for...in`, and `for await...of`), but the plan
      called for narrowing to "for_in_statement with the `await` token
      child". Broader application is plausibly desirable (plain
      `for (const x of req.body)` benefits from the same iterator-text
      classification), but the divergence from the plan was not
      requested. Decide: keep the broader rewrite (and update the plan
      retroactively in commentary) or narrow to the await-token case.
- [ ] Phase 04 audit — `FuncKey.namespace` package prefix is wired
      via a new helper `FuncSummary::func_key_with_resolver` but no
      call site uses it yet. The plan called this out explicitly
      ("No resolver consumer turns this on yet — Phase 10 does"), so
      the deferral is intentional, but phase 10 must remember to
      switch JS/TS pass-1 summary insertion in `scan_filesystem`
      (`local_gs.insert(s.func_key(Some(&root_str)), s)`) and
      `scan_with_index_parallel` to the new helper. SQLite caches of
      summaries written under the old format will need a rebuild on
      first scan after the cutover.
- [ ] Phase 04 audit — the plan said "stash the resolved key on
      each import node so passes 1 and 2 can use it" but the actual
      stash is at the file level (`FileCfg.resolved_imports` plus a
      project-wide `ImportTable` keyed by importer path). Per-import
      AST-node stashing would let phases 05/09/10 look up a specific
      `import_clause` node's resolved file without re-parsing the
      file's import list. Park because the file-level lookup
      (`graph.imports_for(file)`) covers the use cases described in
      phases 05/09/10 deliverables; revisit only if a downstream
      consumer needs node-precise resolution.
- [ ] Phase 04 audit — the resolver only consumes JS/TS imports.
      Python `from X import Y`, Java `import a.b.C;`, and Rust
      `use ::path` already have separate resolvers
      (`cfg::imports::extract_import_bindings`, `rust_resolve.rs`).
      A unified `Imports` table covering every language would let
      cross-file taint use a single API; out of scope for the TS/JS
      foundation phase.
- [ ] Phase 04 audit — `package_for` returns the deepest-root
      package, but `package_entry_main` only honours the entry's
      manifest `main`/`module`/`types` field. Workspaces that ship
      `exports` maps (subpath exports, conditional exports) will
      fall back to `index.{ext}` lookup and miss explicit subpath
      definitions. Park, real fixtures using `exports` haven't
      surfaced in the recall corpus yet; revisit when phase 09/10
      finds a recall gap traceable to this.
- [ ] Phase 04 / recall_gaps mismatch — the phase header table in
      `tests/recall_gaps.rs` maps `jsx_dangerous_html` to phase 04,
      but the phase 04 prompt the implementer received explicitly
      forbids un-ignoring any new gap test ("nothing new un-ignored
      here, the resolver feeds a `FuncKey.namespace` field that is
      currently unused at the resolution site — Phase 10 turns it
      on"). The test stays ignored; whichever phase actually
      delivers JSX-rendered-html taint coverage (likely phase 10
      once the resolver is consumed, or a dedicated phase 04b) must
      flip the `#[ignore]` and provide the fixture. Update the
      header table at the same time so the in-file map matches the
      runner's plan.
- [ ] Phase 04 audit — `ModuleGraph::imports_for` returns
      `Vec<ImportBinding>` rather than the `&[ImportBinding]`
      slice the plan specified. The implementer wrapped the
      `ImportTable` in an `RwLock` so per-file entries can be
      written concurrently from rayon CFG workers, which forces a
      clone on every read. Either pre-populate the table before
      pass 1 (drops the lock and restores the slice signature) or
      accept the divergence and update the plan signature
      retroactively.
- [ ] Phase 04 audit — `strip_jsonc` in `src/resolve/mod.rs` is
      byte-oriented (`out.push(b as char)`) and corrupts non-ASCII
      bytes inside JSON strings: a UTF-8 multi-byte sequence is
      re-encoded as two-byte UTF-8 per original byte before
      `serde_json` parses it, garbling the content. tsconfig /
      package.json files with non-ASCII names, paths, or comments
      will misparse or silently drop characters. Fix: iterate by
      `char` (or copy non-ASCII bytes through verbatim) so the
      output stays valid UTF-8.
- [ ] Phase 04 audit — no test exercises the JS/TS import
      extraction wired into `ParsedFile::from_source`. The new
      `src/resolve/tests.rs` only covers `resolve_specifier`;
      nothing parses `tests/fixtures/resolver/apps/web/src/index.ts`
      end-to-end and asserts that `ModuleGraph::imports_for` returns
      the expected `ImportBinding` rows for the relative, scoped,
      alias, and `node:*` specifiers it imports. Add a parsed-file
      integration test before phase 09/10 starts depending on the
      file-level binding view.

## Deferred phases

(none)
