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

## Deferred phases

(none)
