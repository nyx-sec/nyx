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
      `for_await_of_stream`; phase 06 did it for `jsx_dangerous_html`
      (sink_line = 8 on `page.tsx`, the `__html: input` value span);
      `orm_builders`, `ssrf_url_builders`, `cross_package_ipa`, and
      `nextjs_entrypoints` still own their own.
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
- [x] Phase 03 audit — `tests/fixtures/realistic/async_await/handler.ts`
      was added (TS counterpart to phase 02's `handler.js`) but no
      `recall_gaps` test asserted a finding against it; only the
      pre-existing `async_await` test fired, and it pinned to
      `handler.js`.  Decision: add the assert.  The `async_await`
      test now asserts both the JS and TS findings (sink_line 5 on
      `handler.ts`, source_line 3 — the typed-formal `req: { body:
      string }` parameter — picked up by the typed-extractor
      pipeline's parameter-as-source tagging).
- [x] Phase 03 audit — `src/cfg/mod.rs` for_in_statement text rewrite
      applies to *all* JS/TS `for_in_statement` nodes (i.e. every
      `for...of`, `for...in`, and `for await...of`).  Decision:
      keep the broader rewrite.  The iterator-text-classification
      semantics are uniform across `for...of`, `for...in`, and
      `for await...of` — narrowing to the await-token case would
      create an arbitrary distinction the source rules would have
      to mirror, while keeping it broad lets plain
      `for (const x of req.body)` and `for (const k in process.env)`
      pick up the same source taint without bespoke handling.
      Inline comment in `push_node` records the rationale.
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
- [x] Phase 04 / recall_gaps mismatch — the phase header table in
      `tests/recall_gaps.rs` mapped `jsx_dangerous_html` to phase 04,
      but the phase 04 prompt forbade un-ignoring any new gap test.
      Phase 06 actually delivers JSX-rendered-html taint coverage; the
      header table is updated and the test is now un-ignored against
      `page.tsx` / `page_safe_literal.tsx` / `page_indirect.tsx`.
- [ ] Phase 04 audit — `ModuleGraph::imports_for` returns
      `Vec<ImportBinding>` rather than the `&[ImportBinding]`
      slice the plan specified. The implementer wrapped the
      `ImportTable` in an `RwLock` so per-file entries can be
      written concurrently from rayon CFG workers, which forces a
      clone on every read. Either pre-populate the table before
      pass 1 (drops the lock and restores the slice signature) or
      accept the divergence and update the plan signature
      retroactively.
- [x] Phase 04 audit — `strip_jsonc` in `src/resolve/mod.rs` is
      byte-oriented (`out.push(b as char)`) and corrupts non-ASCII
      bytes inside JSON strings: a UTF-8 multi-byte sequence is
      re-encoded as two-byte UTF-8 per original byte before
      `serde_json` parses it, garbling the content. tsconfig /
      package.json files with non-ASCII names, paths, or comments
      will misparse or silently drop characters. Fixed by switching
      the accumulator to `Vec<u8>` and writing bytes through verbatim
      (UTF-8 continuation bytes are 0x80..=0xBF and never collide
      with the ASCII tokens the comment/string/trailing-comma
      scanner inspects, so byte-level scanning stays correct).
- [x] Phase 04 audit — no test exercises the JS/TS import
      extraction wired into `ParsedFile::from_source`. The new
      `src/resolve/tests.rs` only covers `resolve_specifier`;
      nothing parses `tests/fixtures/resolver/apps/web/src/index.ts`
      end-to-end and asserts that `ModuleGraph::imports_for` returns
      the expected `ImportBinding` rows for the relative, scoped,
      alias, and `node:*` specifiers it imports. Added
      `parses_imports_from_fixture_file` in `src/resolve/tests.rs`:
      parses the fixture with tree-sitter-typescript, runs
      `extract_resolved_imports` against it, and asserts on each of
      the five binding shapes (relative `./foo`, parent-relative
      `../bar/baz`, scoped package `@scope/util`, tsconfig alias
      `@/lib/x`, `node:fs/promises` builtin including the
      `promises as fs` alias preserving `fs` as the local name).
- [ ] Phase 05 audit — `cfg::imports::extract_local_import_view`
      duplicates ~80% of `resolve::extract_resolved_imports`. The
      gated post-pass needs the local-name → source-module view at
      `build_cfg` time, when the resolver-backed `ImportTable` is
      not yet populated. A future cleanup could collapse them by
      moving import-clause extraction into a shared, resolver-free
      walker that both the resolver and the gated post-pass call.
- [ ] Phase 05 audit — `TypeKind::FileSystemPromisesNs` constructor
      mapping in `type_facts.rs::constructor_type` only matches the
      exact callee strings `fs.promises`, `require('fs').promises`,
      and the double-quoted / `node:fs` permutations. The
      receiver-type fallback path therefore fires only when an SSA
      `Call` op carries that exact text. The destructured-assignment
      shape `const fsp = fs.promises;` (a member-access RHS, not a
      `Call`) is not yet covered. Wire FieldProj-driven narrowing
      (when the receiver of `.promises` is `FileSystemNs`-typed,
      project to `FileSystemPromisesNs`) when a real fixture
      surfaces it.
- [ ] Phase 05 audit — `gate_satisfied()` in `labels/mod.rs`
      hard-codes the `FileSystemPromisesNs` receiver-type prefix
      that satisfies `LabelGate::ImportedFromModule`. If a future
      gate ships for another module (e.g. `node:child_process`
      promises wrapper) we'll need a registry mapping
      `LabelGate::ImportedFromModule(modules)` to the set of
      receiver-type prefixes that count as a witness, instead of
      the single hard-coded match.
- [ ] Phase 05 audit — `JS_TS_HANDLER_PARAM_NAMES` auto-seeding in
      the SSA layer has no relation to the gated rule, but Phase 05
      fixtures revealed that `req.body.path` flows through `req`
      → `path` without explicit auto-seeding because the express
      `Request` typed-extractor pipeline already lights up the
      `req.body` source. If a fixture stops firing because the
      handler-param auto-seed and Phase 05 gate disagree on which
      identifier carries taint, audit `is_js_ts_handler_param_name`
      first.
- [ ] Phase 05 fixture cleanup — the four fs/promises fixtures live
      in a shared `tests/fixtures/realistic/fs_promises/` directory
      because `scan_fixture()` accepts a directory, not a file.
      Each `fs_promises_*` test re-scans the entire directory; this
      multiplies wall time on cold caches. Once a future phase
      teaches the harness to scan a single file (or splits the
      directory), trim the redundant scans.
- [x] Phase 05 audit — `tests/recall_gaps.rs` header table (lines
      35-44) is stale: claims phase 03 owns `fs_promises`, but the
      actual phase 03 (Promise callbacks) added `promise_then_*` /
      `promise_all_*` / `for_await_of_*` tests, and phase 05
      replaced `fs_promises` with `fs_promises_readfile` /
      `_open` / `_node_import` / `_safe_userfn`.  Verified the
      table on 2026-05-07 — phase rows now reflect the actual
      `fn` names: phase 02 `async_await`; phase 03 the four promise
      tests (`promise_then_callback`, `promise_all_taint`,
      `for_await_of_stream`, `promise_then_chain_reentrant`); phase
      05 the four `fs_promises_*` tests; phase 06
      `jsx_dangerous_html`; phase 07 `orm_builders`; TBD the three
      remaining ignored tests.  No churn needed.
- [x] Phase 05 audit — `type_facts.rs::constructor_type` exact-string
      arms `"require('fs').promises"`, `"require(\"fs\").promises"`,
      `"require('node:fs').promises"`, and `"require(\"node:fs\").promises"`
      are dead in practice: SSA decomposes member-of-call into
      separate Call + FieldProj ops, so the full expression text
      never reaches `constructor_type` as a callee string. The
      `"fs.promises"` arm has the same shape (member access, not a
      call) and likely also never fires. Removed the JS/TS branch's
      five exact-string arms; `FileSystemPromisesNs` is reached via
      `cfg::apply_gated_label_rules` instead. Comment on the
      `TypeKind::FileSystemPromisesNs` doc updated to record the
      decision.
- [ ] Phase 05 audit — `extract_local_import_view` handles
      `import * as fsp from 'fs/promises'` (namespace_import) and
      `const { readFile } = require('fs/promises')` (object_pattern
      destructuring), but no recall_gaps fixture exercises either
      shape. The four shipped fixtures cover only the named-import
      form. Add positive fixtures for the namespace-import and
      require-form shapes before relying on those code paths.
- [ ] Phase 05 audit — `cfg::apply_gated_label_rules` re-runs
      `classify_all_ctx`, which re-runs the entire flat
      `classify_all` pipeline, for every call node in every JS/TS
      file with at least one import. Once the gated registry
      grows beyond the single fs/promises rule, factor out a
      `classify_gated_only` helper so the post-pass skips the
      redundant flat-rule scan it has already done during initial
      classification.
- [x] Phase 06 audit — `utils::ext::lowercase_ext` collapses both
      `.ts` and `.tsx` to the slug `"ts"`, masking the JSX/TSX
      distinction.  Phase 06 worked around this in
      `ast::lang_for_path` with an early-return on the raw path
      extension that selects `LANGUAGE_TSX` for `.tsx` files, but
      the original match block carried a dead arm (the `.tsx`
      collapsed to `Some("ts")` and was caught by the early-return
      before falling through; the parallel `Some("jsx") =>` arm
      was unreachable because `lowercase_ext` has no `jsx` mapping
      and the early-return on raw extension `Some("jsx")` already
      consumed every JSX file).  Removed the dead `Some("jsx") =>`
      arm; the early-return on raw `tsx`/`jsx` is now the canonical
      path for JSX-aware grammar selection.
- [ ] Phase 06 audit — `Kind::JsxAttr` is a unit variant rather
      than the `JsxAttr { name: SmolStr }` variant the phase
      prompt requested.  Reason: `Kind` must remain `Copy` to fit
      `phf_map` storage, and the static KINDS map can only
      construct values from const expressions.  The attribute
      name is read from the AST at the consumption site
      (`jsx_attr_name_is`) instead.  Switch to a fielded variant
      (and drop `Copy`) only if a future phase needs name-bearing
      Kind variants for additional JSX-specific dispatch (e.g.
      multiple synthesised callees per attribute name); today
      one shape (`dangerouslySetInnerHTML`) is enough.
- [ ] Phase 06 audit — JSX synthesis is hooked into the wrapping
      arms (`Kind::Return`, `Kind::CallWrapper`, `Kind::Assignment`,
      and the wildcard `_` fallback).  JSX expressions inside
      conditional expressions, ternary RHS branches, or other
      unusual containers may not surface a `jsx_attribute` to the
      helper because the wrapping arm short-circuits before the
      JSX subtree is reachable.  Out of scope until a real fixture
      surfaces a missed shape; revisit by lifting the helper to a
      tree-wide post-pass over `build_cfg`.
- [ ] Phase 06 audit — sanitizer-aware `__html` stripping only
      recognises the shape `__html: SANITIZER(args)` where the
      callee classifies as `Sanitizer` under
      `classify_all`.  Multi-step sanitization
      (`__html: pipe(input, sanitize, escape)`,
      `__html: chain.escape().sanitize()`) and shapes where the
      sanitised value is bound to a separate variable
      (`const clean = sanitize(x); __html: clean`) fall through.
      Variable-bound sanitization works today via SSA value
      tracking on the bound name; the chained / higher-order
      shapes need a richer recogniser.  Defer until a fixture
      surfaces an FP.
- [ ] Phase 06 audit — JSX is recognised only for React TSX/JSX
      via the tree-sitter-typescript and tree-sitter-javascript
      grammars.  Other JSX-flavour template languages (Svelte
      `bind:innerHTML`, Vue `v-html`, Solid's
      `innerHTML` directive) carry the same XSS-by-default
      semantics but use entirely separate grammars.  Out of
      scope; revisit when a gap test arrives for one of those
      ecosystems.
- [ ] Phase 07 audit — `ssa::type_facts::constructor_type` (TS/JS)
      assigns the new ORM TypeKinds (`Sequelize`, `TypeOrmRepo`,
      `TypeOrmManager`, `MikroOrmEm`) by suffix-matching alone, with
      no import-table gate. The phase 07 plan called for
      "Use Phase 04's import table to only assign the TypeKind when
      the symbol resolves to the real ORM package", but threading the
      import map through `optimize_ssa` → `analyze_types_with_param_types`
      → `constructor_type` is invasive (six call sites). The leaf-suffix
      names are distinctive enough that misfires are unlikely on real
      code; revisit when a fixture surfaces a false positive (e.g. an
      app-internal class named `Sequelize` with a `.literal()` helper).
- [ ] Phase 07 audit — `TypeKind::DrizzleSqlBuilder` and its
      `label_prefix` + `DrizzleSqlBuilder.raw` flat rule are wired
      end-to-end, but the variant is never assigned by
      `constructor_type` because the imported `sql` symbol from
      `drizzle-orm` is not produced by a constructor call (just an
      import binding). Phase 07 ships the leading-identifier
      `LabelGate::ImportedFromModule(&["drizzle-orm"])` shape via
      GATED_LABEL_RULES instead, so the TypeKind path is reachable
      only by future SSA-time import-aware tagging. Either remove the
      variant or land a tagging pass that types Param/Source values
      whose name resolves to an imported binding.
- [ ] Phase 07 audit — receiver-type-qualified ORM sinks
      (`TypeOrmRepo.query`, `MikroOrmEm.execute`, etc.) are flat
      label rules, so they fire on taint into ANY positional argument
      rather than gating to the SQL-template position. The negative
      parameterised fixture (`sqli_typeorm_safe_parameterized.ts`)
      passes only because no user input flows into the call at all;
      a real-world `repo.query("SELECT $1", [tainted])` would FP.
      Wire SinkGate semantics through the type-qualified resolver path
      so `TypeOrmRepo.query` carries `payload_args = &[0]` and
      bind-array taint (arg 1+) is suppressed.
- [ ] Phase 07 audit — `LabelGate::FileImportsModule(&["knex"])` for
      Knex `whereRaw` / `orderByRaw` / `havingRaw` fires whenever any
      file-local binding maps to `knex`, including peripheral imports
      (e.g. `import { Knex } from 'knex'` for type-only use). A
      tighter gate would witness only the query-builder factory call
      (`const db = knex({...})`) but needs receiver-type tracking
      that constructor_type does not currently produce for the bare
      `knex` callee. Revisit when an FP surfaces.
- [ ] Phase 07 audit — no positive MikroORM fixture ships in the
      `orm_builders` directory. The `MikroOrmEm.execute` rule + the
      `createEntityManager` constructor_type entry are wired but only
      validated through the type system, not by a scan-time fixture.
      Add `sqli_mikroorm_execute.ts` once a real fixture pattern is
      identified, or drop the rule until then.
- [ ] Phase 07 audit — `Sequelize` constructor maps to
      `TypeKind::Sequelize` purely from leaf-suffix matching on
      `new_expression`. The mapping fires on `new Sequelize(...)` but
      not on the alternate factory shape `Sequelize.define(...)`
      (which returns a Model class, distinct from the Sequelize
      instance). The plan listed `sequelize.literal` as a factory in
      the constructor_type table, but `sequelize.literal()` returns a
      Literal value, not a Sequelize instance — typing that result as
      `Sequelize` would mis-shape. Skip until a fixture surfaces a
      gap.
- [x] Phase 07 audit — **`await` blocks receiver-type-qualified sink
      resolution**. Reproduction: `await repo.query("SELECT … '" + name
      + "'")` after `const repo = getRepository(User)` did NOT fire
      `TypeOrmRepo.query` SQL_QUERY; the same call without `await`
      fired HIGH at the call site. Root cause: `cfg::literals::find_call_node`
      only descended two levels of children, but the AST for
      `const x = await foo(y)` is four levels deep
      (`lexical_declaration > variable_declarator > await_expression
      > call_expression`), so `call_ast = None`, receiver extraction
      was skipped, and the SSA Call op was emitted with
      `receiver: None`.  Without a receiver SSA value the type-fact
      lookup in `resolve_type_qualified_labels` had nothing to anchor
      on.  Fixed by teaching `find_call_node` to descend transparently
      through `Kind::AwaitForward` wrappers (`await_expression`,
      `yield_expression`).  The companion finding-attribution fix
      lifts `effective_sink_caps` into the Diag's
      `evidence.sink_caps` so receiver-qualified sinks (whose CFG
      node carries no flat label) report the correct cap downstream
      instead of `0`.  Test `sqli_typeorm_query.ts` retargeted to
      sink_line 16 (the actual `repo.query(...)` line) and now uses
      `assert_finding_with_cap` to require `Cap::SQL_QUERY`, so a
      coincidental XSS finding on the adjacent `res.json(rows)` line
      can no longer mask a missing TypeORM rule.  Same recall now
      flows through to all other receiver-type-qualified sinks
      (Sequelize, MikroORM, etc.) when wrapped in `await`.

## Deferred phases

(none)
