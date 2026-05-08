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
      phase 08 did it for `ssrf_url_builders` (five positives +
      cap-aware assertion + origin-locked negative);
      phase 09 did it for `cross_package_ipa`
      (`handler.ts:7` source 5 unsafe positive + silent-at-`handler.ts:13`
      sanitiser negative); `nextjs_entrypoints` still owns its own.
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
- [ ] Phase 08 audit — the URL-constructor recognition path in
      `analyze_types`, `transfer_abstract`, and the URL-arg
      taint-propagation rule in `transfer_inst` all consult
      `info.call.outer_callee` because the CFG-level text rewrite
      for source-bearing assignments
      (`const u = new URL(req.body.path, …)` →
      `info.call.callee == "req.body.path"`) drops the original
      constructor identifier from the SSA-level `callee` field. Other
      `constructor_type` consumers still rely on `callee` alone.
      Sweep them and route every one through the same
      `callee || outer_callee` fallback so this CFG-level rewrite
      cannot silently disable type inference for any other
      constructor (e.g. ORM constructors with member-source args).
      Out of scope for Phase 08 because URL is the only
      currently-modelled constructor where the rewrite is observable
      against a Phase-08 fixture.
- [ ] Phase 08 audit — `new URL(path, base)` abstract-string seeding
      requires `base` to be a syntactic string literal (read from
      `info.call.arg_string_literals`). A two-arg form whose base is
      a constant identifier
      (`const BASE = "https://api.cal.com"; new URL(req.body.path,
      BASE);`) won't be recognised because the base value is an SSA
      `Param`/`Const` reference rather than a literal-positioned arg.
      Bridge through `abs.get(base_v).string` (singleton `domain`)
      when that shape becomes load-bearing. Park because const-base
      forms are uncommon in the realistic SSRF corpus.
- [ ] Phase 08 audit — the `set`/`append` back-taint rule walks the
      FieldProj receiver chain via
      `receiver_candidates_for_type_lookup`, which only follows
      `FieldProj.receiver` and (for Rust) nested `Call.receiver`
      hops. A JS/TS chain that interposes a CallMethod (e.g.
      `getUrl().searchParams.set(k, v)`) won't surface the original
      URL value because the chain stops at the intermediate Call.
      Add JS/TS-aware Call-receiver hops to the walker if a fixture
      surfaces this pattern.
- [ ] Phase 08 audit — the prompt prescribed extending
      `src/taint/ssa_transfer/events.rs::collect_block_events` to
      collect first-arg URL-typed taint and object-literal `url`
      property taint for SSRF sinks (with a possible new
      `NodeInfo.arg_object_props` field). The two relevant fixtures
      (`ssrf_fetch_url_typed_arg.ts`, `ssrf_fetch_object_form.ts`)
      already pass without that extension because (a) the URL-typed
      first arg is fed by the new `transfer_inst` constructor-
      propagation rule which paints the SSA value tainted before the
      sink fires, and (b) the existing destination-aware sink filter
      already handles `fetch({url: ...})`. Park the events.rs change
      until a fixture surfaces a path the current routing misses
      (e.g. an object-literal whose property is reached only via a
      `Spread` or nested object).
- [ ] Phase 09 audit — `build_cross_package_func_keys` uses plain
      `crate::symbol::normalize_namespace` (scan-root-relative path)
      rather than the package-prefixed `namespace_with_package` the
      phase prompt described. Reason: pass-1 SSA summary keys
      produced by `lower_all_functions_from_bodies` set
      `key.namespace = namespace.to_string()` from the plain
      `normalize_namespace` form passed in by `analyse_file_with_lowered`
      / `extract_ssa_artifacts_from_file_cfg`, so step 0.7's lookup
      must use the same shape to find anything in `gs.ssa_by_key`.
      Migrating SSA summary storage to `namespace_with_package`
      (matching how FuncSummary keys are now built via
      `func_key_with_resolver`) would let step 0.7 use the canonical
      package-prefixed form and would unify the two sides of
      `GlobalSummaries`. Park because the unified migration touches
      `lower_all_functions_from_bodies`, `extract_ssa_artifacts_from_file_cfg`,
      and the call-graph builder, and today's plain-namespace path
      already produces correct cross-package recall on the Phase 09
      fixture.
- [ ] Phase 09 audit — the cross-package fixture renames the
      passthrough function from the phase prompt's `escapeHtml` to
      `escapeHtmlNoop` because `escapeHtml` is in the JS sanitizer
      matcher list (`src/labels/javascript.rs`) and would be cleared
      at the consumer call site by the CFG-level intrinsic
      `Sanitizer(HTML_ESCAPE)` label, masking whether step 0.7's
      cross-package summary lookup actually fired. The matcher list
      now strictly captures community-conventional sanitizer leaf
      names; if a future fixture wants to assert step 0.7 against a
      function whose name *is* in that list, the SSA summary path
      must be made authoritative over the leaf-name label (i.e. the
      summary's `propagating_params` should override an intrinsic
      `Sanitizer` label when the summary says taint flows through).
      Park; today the rename keeps the test honest.
- [ ] Phase 09 audit — the cross-package sanitizer fixture
      (`packages/util/src/strip.ts`) implements `stripTags` as a
      wrapper around `encodeURIComponent` instead of the regex-based
      `s.replace(/<[^>]*>/g, "")` shape the phase prompt suggested.
      Reason: Phase 22's `detect_replace_sanitizer` in
      `src/symex/strings.rs` only flags regex-replace as an
      *informational* sanitizer (witness quality only) and does NOT
      clear taint, so a `replace`-only function summary is a
      passthrough indistinguishable from `escapeHtmlNoop`. Promoting
      regex-replace to taint-clearing would require lifting Phase 22
      from informational to load-bearing, which interacts with every
      replace-sanitizer FP-prone shape. Park; today `encodeURIComponent`
      gives the safe path a real summary-carried sanitize transform.
- [ ] Phase 09 audit — `SsaTaintTransfer::cross_package_imports` is
      forwarded as `None` on the inline-analysis `child_transfer`
      (see `src/taint/ssa_transfer/mod.rs::inline_analyse_callee`)
      because the inlined callee body lives in another file with its
      own import view, not the caller's. Forwarding the caller's map
      would resolve the callee's local names against the wrong
      package boundary. The right fix is to fetch the callee file's
      own `cross_package_imports` (likely keyed by the callee's
      file path on `GlobalSummaries` or via a new `bodies_by_key`
      sibling), but doing so requires the per-file map to be
      addressable across files. Park; today the inlined frame
      simply skips step 0.7 inside, which only loses cross-package
      IPA *transitive through* an inlined callee.
- [ ] Phase 09 audit — step 0.7 currently scans
      `GlobalSummaries::snapshot_ssa()` keys linearly for each
      cross-package callee that does not hit the existing flat
      paths. The cost is `O(|ssa_by_key| × cross-package-call-sites)`
      per file. On the bench corpus this is small (handful of
      cross-package calls per file) but a project-scale scan with
      thousands of cross-package call sites and tens of thousands of
      stored SSA summaries would benefit from a `(lang, namespace,
      name)`-indexed sibling map on `GlobalSummaries`. Park until
      a profile run flags step 0.7 as a hot path.
- [ ] Phase 09 audit — the recall_gaps test asserts the unsafe
      finding fires at `handler.ts:7` (source 5) and that the safe
      finding stays silent at `handler.ts:13`, but does NOT assert
      the propagation step is annotated as going through
      `@scope/util/src/sanitize.ts::escapeHtmlNoop` the way the
      phase prompt aspired to. The harness in
      `tests/common/recall.rs` only inspects rule_id / file_suffix
      / sink_line / source_line on `Diag`. Adding propagation-trace
      attribution would require the harness to read
      `Diag.evidence.flow_steps` (or equivalent) and is out of
      scope for the recall lift. Park; the cross-package recall
      result is already proved by the positive + negative pair.

- [ ] Phase 10 audit — `detect_entries_in_file(tree, bytes, path,
      lang_slug)` returns a `HashMap<(usize, usize), EntryKind>` keyed
      by tree-sitter byte span, not the `Vec<(FuncId, EntryKind)>` the
      phase prompt described.  Reason: the consumer (`build_cfg` →
      `FileCfg::entry_kinds`) matches against `BodyMeta::span` to
      attach the tag to summaries, and the `ParsedFile` /
      `ModuleGraph` parameters from the prompt are not needed —
      file-level, function-level, and path-based detection is purely
      syntactic.  A `FuncId`-keyed shape would force a separate body
      identity lookup at every consumption site.  Park; revisit if a
      future caller needs `FuncId`-keyed output.
- [ ] Phase 10 audit — `EntryKind::FormAction` is part of the on-disk
      shape but is **not produced** by `detect_entries_in_file` today.
      Reason: no fixture in the recall-gap suite required `<form
      action={fn}>` recognition; the variant is reserved so older
      serialised summaries deserialise cleanly when the recogniser
      expands.  Add a fixture and a JSX-attribute-walker arm in
      `entry_points/mod.rs` when a downstream consumer needs it.
- [ ] Phase 10 audit — `Request.json` / `Request.formData` /
      `Request.text` / `Request.url` / `Request.headers.get` are
      modelled as `Source(Cap::all())` label rules rather than as
      receiver-forwarding rules (which would propagate the
      receiver's taint verbatim).  Reason: when the App Router
      handler's first formal is auto-seeded as
      `Source(UserInput)` by `run_ssa_taint_internal`, a Source
      label on the receiver-method rewrite produces the same
      sink-reachability without needing a separate forwarding arm.
      Headers/url additionally expose adversary state directly, not
      just propagate the receiver.  If a future fixture surfaces a
      path where the receiver carries a non-source-tagged taint
      that must survive `req.json()` verbatim, swap the Source
      labels for receiver-forwarding rules in
      `taint/ssa_transfer/mod.rs::transfer_inst`.
- [ ] Phase 10 audit — the App Router `TypeKind::Request` override
      on `param_types[0]` happens in two places:
      `taint::lower_all_functions_from_bodies_inner` (the cached
      pass-1 lowering) and `taint::analyse_body_with_seed` (the
      per-body pass-2 analysis).  Reason: the param-types vector
      flows through `optimize_ssa_with_param_types` separately on
      each path and there is no shared upstream point where the
      override could be applied once.  A single override site would
      require migrating `BodyMeta::param_types` from
      `Vec<Option<TypeKind>>` to a thicker carrier that records
      "entry-kind-derived overrides" so the type-fact pass can read
      both layers.  Park; today the duplication is ~12 lines and
      keeps the override visible at each consumption point.
- [ ] Phase 10 audit — `SsaTaintTransfer::cross_package_imports`
      is forwarded as `None` on the inline-analysis `child_transfer`
      (carried over from Phase 09).  An entry-point body that
      transitively inlines a callee whose body is in a different
      package will not benefit from step 0.7 inside the inlined
      frame.  Same root cause as the Phase 09 audit; the Phase 10
      seeding pass does not change that.
- [ ] Phase 10 audit — entry-point seeding fires only on functions
      whose `entry_kind` is set on the `SsaFuncSummary` reachable
      via `(name, container, disambig)` lookup against the
      file-level `entry_kinds` map.  Anonymous arrows passed
      directly to e.g. `app.use((req, res) => ...)` are not yet
      recognised — they have no name to key against.  The current
      JS handler-param auto-seeder (`is_js_ts_handler_param_name`)
      already handles `(req, res)` shapes; the Phase 10 seeding
      path is additive on top.
- [ ] Phase 11 audit — baseline relocation. Phase 11 deliverables
      named `.pitboss/play/recall_targets/<target>.json` and
      `.pitboss/play/recall_targets/perf_after.txt`, but pitboss hard
      rule 2 forbids implementer agents from writing under
      `.pitboss/`. Phase 11 relocated the artifacts to
      `tests/recall_targets/` (next to `tests/recall_gaps.rs`,
      mirroring the Phase 01 precedent for
      `tests/recall_gaps_baseline.json`). If a future phase needs
      these mirrored back into `.pitboss/play/`, the runner — not an
      implementer — must copy them.
- [ ] Phase 11 audit — three of four target baselines ship as
      placeholders. Only `cal_com.json` was captured against a real
      clone (`/Users/elipeter/oss/cal.com` @ `d278d6c9`, 662 findings).
      `vercel_commerce.json`, `shadcn_examples.json`, and
      `blitz_apps.json` exist with the correct schema but
      `findings: []` and `pinned_commit: "unknown"`. Reason: only
      cal.com was already cloned locally; pitboss implementer agents
      run sandboxed without network egress, so the other three
      checkouts could not be fetched. Resolution: clone each target
      and run `scripts/validate_recall.sh <target> <clone> --capture`
      to populate. The `validate_real_world_targets` schema test
      passes against placeholders because `[]` is a valid
      `findings` array.
- [ ] Phase 11 audit — cal.com verdict triage is sparse.
      `cal_com.json` carries 662 findings; only 4 are hand-labelled
      `FP` (the `ts.crypto.math_random` hits inside
      `apps/web/playwright/` test fixtures). The remaining 658 stay
      `verdict: "needs_review"`, which is the placeholder verdict
      `validate_recall.sh --capture` writes by default. Sweeping
      these into `TP`/`FP` is bounded human work — read the source
      flow at each `path_suffix:line` and mark accordingly. Future
      precision work (FP-removal phases) needs the labelled set to
      measure improvement, but the schema test does not require
      every entry to be triaged.
- [ ] Phase 11 audit — `validate_recall.sh` always re-builds and
      re-runs nyx end-to-end (no cache reuse). On cal.com (340 MB)
      the warm-cache scan is ~50 s, which is fine for hand
      validation but expensive enough that future cross-lang
      validation phases (16/17) will want a `--from-snapshot
      <prior_run.json>` input mode that skips the scan and just
      diffs two captured JSONs. Park; today the bottleneck is
      acceptable on the listed four targets.
- [ ] Phase 11 audit — perf baseline only records
      `tests/fixtures/`-corpus throughput (1.55 s warm,
      1143 findings on 2026-05-08). Phase 01's baseline did not
      capture perf timings, so there is no apples-to-apples
      Phase 01 → Phase 11 delta. The first cross-phase perf delta
      will appear in Phase 17's `perf_after_xlang.txt` (which
      compares against the Phase 11 number recorded here). Add a
      retroactive Phase 01 perf line if a future replan asks for
      one.

- [ ] Phase 12 audit — the Rust `handler.rs` fixture uses a hand-rolled
      `Headers::get` async method rather than a real axum extractor
      (e.g. `Body::data().await`).  Reason: nyx is text-driven, so the
      fixture only needs to match the existing `headers.get` Source
      matcher; pulling in axum / hyper as test deps would inflate the
      fixture footprint.  If a future phase wants a real axum-extractor
      shape exercised end-to-end, add a `Source` rule for
      `Body.data` / `Body.collect` and reshape the fixture.

- [ ] Phase 12 audit — `is_promise_combinator("rust", ...)` recognises
      the qualified macro paths (`tokio::join`, `futures::join`, plus
      `try_*`) but not the bare `join!` / `try_join!` form that fires
      after `use tokio::join;`.  `extract_arg_uses` accepts the bare
      names so a future combinator-recognition extension can light them
      up, but the conservative posture today is to not match bare
      `join` (the leaf is too generic; collisions with non-macro user
      callees of the same name would surface as combinators).  Add bare
      recognition behind a per-file import-aware check
      (`use tokio::join;` rebind detection in
      `cfg::imports::extract_local_import_view`) when a real-world
      fixture surfaces the bare-import shape.

- [ ] Phase 12 audit — Python `async for x in stream:` and sync
      `for x in stream:` share the same `for_statement` AST node
      (the `async` token is unnamed).  The iterator-text rewrite in
      `cfg::push_node` therefore fires uniformly, not gated on the
      async modifier.  This is the same pragmatic choice the JS
      branch made (which covers `for`, `for...of`, `for...in`, and
      `for await...of` identically).  If async-iterator semantics
      ever diverge from the sync form (e.g. `__aiter__`-only sources
      that should not light up via the shared rewrite), gate the
      Python rewrite on the presence of an `async` leaf child.

- [ ] Phase 12 audit — `tokio::join!`'s tuple result is currently
      modelled as a single SSA value carrying the union of every
      argument's taint, mirroring the existing JS `Promise.all`
      convention (see Phase 03's deferred per-element-precision
      item).  Field projection (`results.0`) inherits taint via the
      receiver chain, so the recall fixture lights up for the
      union-tainted index.  The same per-element precision lift the
      JS combinator wants would also benefit the Rust tuple form;
      both share the upstream tuple/array-element lattice extension.

- [ ] Phase 12 audit — the new `extract_rust_macro_join_arg_uses`
      helper splits the `token_tree` on `,` leaves to segment
      arguments.  This is correct for simple shapes
      (`tokio::join!(fetch(a), fetch(b))`) and for nested calls,
      because nested `()` groups become inner `token_tree` nodes
      that the splitter walks transparently.  It does NOT special-
      case macro-internal repetition (`token_repetition`) or
      metavariable substitutions, both legal at the grammar level.
      A bug-hunt fixture that lands a `tokio::join!` arg containing
      `$($x:expr),*` would cause arg-grouping to misalign; bridge by
      treating `token_repetition` as a sub-expression boundary if
      that shape becomes load-bearing.

- [ ] Phase 12 audit — the `await_emits_at_most_one_assign_per_node`
      ssa-equivalence test in `tests/ssa_equivalence_tests.rs`
      currently asserts the bound on a single hand-crafted Rust
      fixture (`tests/fixtures/realistic/async_await/await_count.rs`).
      The same invariant holds for every Rust file in the SSA
      corpus, but extending the assertion across the corpus would
      slow this tier from ~10 ms to seconds (every fixture re-lowered
      and re-walked).  Park the corpus-wide variant until a CI
      perf budget for ssa-equivalence-tests is established.

- [ ] Phase 13 audit — Python pathlib FILE_IO sinks
      (`Path.read_text`, `Path.write_text`, etc.) only fire on the
      chained-construction shape `Path(name).read_text()` whose
      paren-strip yields `Path.read_text`.  The receiver-bound shape
      `p = Path(name); p.read_text()` evades the matcher (callee
      text `p.read_text` doesn't suffix-match `Path.read_text`).
      Bridging requires registering `Path` (or `pathlib.Path`) in
      `src/ssa/type_facts.rs::constructor_type` for Python with a
      `TypeKind::FileHandle` mapping plus `FileHandle.read_text` /
      `FileHandle.write_text` etc. matchers in `src/labels/python.rs`.
      Phase 13 deliberately scoped to chain-form-only to keep the
      label rule list compact and avoid over-firing on unrelated
      `*.read_text` / `*.write_text` methods.

- [ ] Phase 13 audit — Java `Path.normalize` Sanitizer rule does
      not fire on the canonical sanitiser chain `base.resolve(name)
      .normalize()` (paren-strip yields `base.resolve.normalize`,
      which suffix-matches neither `Path.normalize` nor `normalize`
      bare).  The Phase 13 sanitized fixture relies on the
      no-sink-reached pattern (`return candidate.toString()`) to
      stay silent rather than the rule firing.  Bridging requires
      either (a) registering `Paths.get` returning
      `TypeKind::FileHandle` in `constructor_type` for Java + a
      `FileHandle.normalize` matcher, or (b) adding a bare
      `normalize` matcher (over-fires on `Locale.normalize`,
      `BigDecimal.normalize`, etc.).  Park: the rule is registered
      for documentation; the Phase 13 acceptance contract only
      requires the sanitized fixture to stay silent.

- [ ] Phase 13 audit — Python `Path.resolve` Sanitizer rule fires
      on any `.resolve()` chained on `Path(...)`; the phase prompt
      asked for `strict=True`-gated activation but the chain text
      `Path.resolve` does not surface keyword-argument values to
      the classify pass.  Adding a `GatedLabelRule` flavour with
      `GateActivation::ValueMatch` on a `strict` kwarg is the
      structural fix.  Park: the non-strict form still resolves
      symlinks and collapses `..` segments, which dominates the
      attack surface; the over-clear FP risk on bare `.resolve()`
      is acceptable.

- [ ] Phase 13 audit — Ruby `Pathname.new(p)` is registered as a
      `Sink(FILE_IO)` per the phase prompt's explicit list.  The
      matcher fires on the canonical-construction shape
      (`Pathname.new(tainted)`) which is the documented
      path-traversal entry point, but a benign program that
      constructs a `Pathname` purely for path-string manipulation
      (without downstream file ops) would surface a FILE_IO
      finding.  No corpus regression observed in `cargo test`,
      but the over-fire risk is real on application code that
      threads `Pathname.new` through utility helpers.  Park:
      monitor real-world recall targets for FP shapes and tighten
      to `Pathname.new` + downstream `.read` / `.write` chain
      detection if needed.

- [ ] Phase 13 audit — Rust sanitized fixture
      (`path_traversal_safe.rs`) takes a `req: Request` parameter
      whose receiver chain `req.headers().get("X-Path").await`
      classifies as `headers.get` (Source).  The `PathBuf::canonicalize`
      / `starts_with(&base)` containment check is the canonical
      Rust path-traversal sanitiser pattern, but the Phase 13
      label rule set does not register a Rust-side sanitiser
      (the phase explicitly listed Python / Java / Go only).
      The fixture stays silent because no `tokio::fs::*` /
      `std::fs::*` sink is reached; the canonicalise-and-validate
      shape demonstrates the safe pattern for human readers
      without needing a label rule.  Add a `Path.canonicalize`
      Sanitizer(FILE_IO) rule in `src/labels/rust.rs` if a future
      fixture lands a sink downstream of the canonical value.

## Deferred phases

(none)
