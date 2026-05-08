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
- [ ] Tighten `ExpectedFinding.sink_line` placeholders. Phase 01 wrote `0`
      for every gap-area test because the fixtures do not exist yet. The
      phase that un-ignores each test must update its `sink_line` (and,
      where stable, `source_line`) to a real fixture line. Phase 03 did
      this for `promise_then_callback`, `promise_all_taint`, and
      `for_await_of_stream`; phase 06 did it for `jsx_dangerous_html`
      (sink_line = 8 on `page.tsx`, the `__html: input` value span);
      phase 07 did it for `orm_builders` (six positives + cap-aware
      assertion on `sqli_typeorm_query.ts`);
      `ssrf_url_builders`, `cross_package_ipa`, and `nextjs_entrypoints`
      still own their own.
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
- [ ] Phase 05 audit — `JS_TS_HANDLER_PARAM_NAMES` auto-seeding in
      the SSA layer has no relation to the gated rule, but Phase 05
      fixtures revealed that `req.body.path` flows through `req`
      → `path` without explicit auto-seeding because the express
      `Request` typed-extractor pipeline already lights up the
      `req.body` source. If a fixture stops firing because the
      handler-param auto-seed and Phase 05 gate disagree on which
      identifier carries taint, audit `is_js_ts_handler_param_name`
      first.
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
- [ ] Phase 06 audit — JSX is recognised only for React TSX/JSX
      via the tree-sitter-typescript and tree-sitter-javascript
      grammars.  Other JSX-flavour template languages (Svelte
      `bind:innerHTML`, Vue `v-html`, Solid's
      `innerHTML` directive) carry the same XSS-by-default
      semantics but use entirely separate grammars.  Out of
      scope; revisit when a gap test arrives for one of those
      ecosystems.
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

## Deferred phases

(none)
