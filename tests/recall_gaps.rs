//! # Recall-gap integration harness (phase 01 baseline)
//!
//! Pitboss phase 01 stands up the skeleton; phases 02–11 grow it. The suite
//! is green on a fresh `master` because every gap-area test starts
//! `#[ignore]`d, so this file compiles and runs without depending on engine
//! work that has not landed yet.
//!
//! ## Where fixtures live
//!
//! Each gap area owns a subdirectory under
//! `tests/fixtures/realistic/<area>/`. The phase that un-ignores a test is
//! responsible for populating its fixture. Fixtures are copied into a fresh
//! tempdir per scan (see [`common::recall::scan_fixture`]) so SQLite,
//! `nyx.conf`, or stray index artefacts cannot leak between tests.
//!
//! ## `ExpectedFinding` shape
//!
//! Each test asserts findings with a tuple of
//! `(rule_id, file_suffix, sink_line, source_line)`:
//!
//! - `rule_id` — exact prefix match on `Diag.id`. Taint findings carry a
//!   trailing ` (source N:M)` suffix that the matcher strips before
//!   comparison.
//! - `file_suffix` — `Diag.path.ends_with(file_suffix)`, which lets callers
//!   ignore the tempdir prefix supplied by the harness.
//! - `sink_line` — exact match on `Diag.line` (1-based).
//! - `source_line` — optional `N` parsed from the ` (source N:M)` suffix
//!   on `Diag.id`. Use `None` when the originating line is unstable across
//!   refactors of the fixture.
//!
//! ## Phase ownership
//!
//! Every phase un-ignores exactly the tests it owns. The mapping is stable:
//!
//! | Phase | Test fn                       |
//! |-------|-------------------------------|
//! | 02    | `async_await`                 |
//! | 03    | `promise_then_callback`,      |
//! |       | `promise_all_taint`,          |
//! |       | `for_await_of_stream`,        |
//! |       | `promise_then_chain_reentrant`|
//! | 05    | `fs_promises_*`               |
//! | 06    | `jsx_dangerous_html`          |
//! | 07    | `orm_builders`                |
//! | TBD   | `ssrf_url_builders`,          |
//! |       | `cross_package_ipa`,          |
//! |       | `nextjs_entrypoints`          |
//!
//! Phase 04 ships the TS/JS module resolver foundation but un-ignores no
//! gap tests of its own — the resolver feeds `FuncKey.namespace` for later
//! phases.  Phases beyond the table may add further `#[ignore]`d tests;
//! do not move tests between owners.

mod common;

use common::recall::{assert_finding, assert_finding_with_cap, scan_fixture, ExpectedFinding};
use nyx_scanner::labels::Cap;
use std::path::Path;

#[test]
fn async_await_js() {
    let findings = scan_fixture("async_await");
    // JS form — exercises the JavaScript `await_expression` KINDS-map entry.
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "handler.js",
            sink_line: 6,
            source_line: Some(4),
        },
    );
    // TS form — same source/sink shape, exercises the TypeScript
    // `await_expression` KINDS-map entry.  Without this assertion the
    // `.ts` fixture was scanned implicitly via `scan_fixture("async_await")`
    // (smoke only), with no positive guarantee that the TS grammar's
    // await-forwarding lowered taint identically.  Source attributes to
    // line 3 (the typed-extractor `req: { body: string }` parameter) —
    // the typed-formal pipeline tags the parameter itself as the taint
    // origin, which is the canonical handler-input shape rather than the
    // intermediate `req.body` access on line 4.
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "handler.ts",
            sink_line: 5,
            source_line: Some(3),
        },
    );
}

/// Phase 12 recall-gap (Python).  tree-sitter-python emits `await x` as a
/// named `await` node (no `_expression` suffix).  Without the
/// `"await" => Kind::AwaitForward` entry in `src/labels/python.rs` and the
/// corresponding `Kind`-driven `is_await_forward` flag in `cfg::push_node`,
/// the engine never models the await boundary as a 1:1 forward and the
/// FastAPI-shape `await request.json()` source never reaches `cursor.execute`.
#[test]
fn async_await_py() {
    let findings = scan_fixture("async_await/handler.py");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "handler.py",
            sink_line: 8,
            source_line: None,
        },
    );
}

/// Phase 12 recall-gap (Python combinator).  `asyncio.gather(...)` is
/// registered as `PromiseCombinatorKind::All` for Python in
/// `is_promise_combinator`; argument taint unions onto the awaited result.
#[test]
fn async_await_py_gather() {
    let findings = scan_fixture("async_await/gather.py");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "gather.py",
            sink_line: 14,
            source_line: None,
        },
    );
}

/// Phase 12 recall-gap (Rust).  `x.await` is now mapped explicitly to
/// `Kind::AwaitForward` in `src/labels/rust.rs`; the `is_await_forward`
/// flag is set via `lookup(lang, ast.kind()) == Kind::AwaitForward`
/// rather than the raw-string `ast.kind() == "await_expression"` check.
/// The header-shape source flows across the await into the
/// `Command::new("sh").arg(&cmd)` shell-injection sink.
#[test]
fn async_await_rs() {
    let findings = scan_fixture("async_await/handler.rs");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "handler.rs",
            sink_line: 26,
            source_line: Some(25),
        },
    );
}

/// Phase 12 recall-gap (Rust combinator).  `tokio::join!(...)` is a
/// `macro_invocation` whose args live inside a `token_tree`.
/// `extract_arg_uses` walks the token_tree splitting on `,` so the SSA
/// Call carries one arg group per future, and
/// `is_promise_combinator("rust", "tokio::join")` routes it through the
/// existing combinator transfer.  The unioned env-var taint flows into
/// `reqwest::get` (SSRF sink).
#[test]
fn async_await_rs_join() {
    let findings = scan_fixture("async_await/tokio_join.rs");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "tokio_join.rs",
            sink_line: 11,
            source_line: None,
        },
    );
}

/// Phase 12 deferred-fix (Rust combinator, bare macro form).
/// `use tokio::join;` brings the macro into scope and the call site uses
/// `join!(...)`.  `cfg::push_node` rewrites the bare macro callee text to
/// `tokio::join` when an import witness is present, so the existing
/// combinator transfer fires the same way as for the qualified form.
#[test]
fn async_await_rs_join_bare() {
    let findings = scan_fixture("async_await/tokio_join_bare.rs");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "tokio_join_bare.rs",
            sink_line: 13,
            source_line: None,
        },
    );
}

/// Phase 03 recall-gap: `.then(cb)` propagates the receiver Promise's
/// resolved value into the callback's first parameter.  The taint trace
/// attributes at the inner `db.query(data)` sink via the callback-pattern
/// emission paired with the chain-hop site promotion that lifts the
/// callback's own-body sink coordinates into the trace finding's primary
/// location.
#[test]
fn promise_then_callback() {
    let findings = scan_fixture("promise_then_callback");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "promise_then_callback.ts",
            sink_line: 9,
            source_line: Some(7),
        },
    );
}

/// Phase 03 recall-gap: `Promise.all([...])` returns a value carrying the
/// union of element taints; `p.then(cb)` then exposes it to the sink at
/// `db.query(items)` via the callback-pattern emission with chain-hop
/// site promotion.
#[test]
fn promise_all_taint() {
    let findings = scan_fixture("promise_all_taint");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "promise_all_taint.ts",
            sink_line: 8,
            source_line: None,
        },
    );
}

/// Per-element precision for `const [a, b] = await Promise.all([safe,
/// tainted])`. The SSA lowering rewrite in src/ssa/lower.rs maps each
/// destructure binding to `Assign(arg_uses[0][i])`, so `a` binds only to
/// the literal `"ok"` and `b` binds only to the tainted `req.body`. The
/// scalar union from `try_apply_promise_combinator` is bypassed for the
/// per-binding values.
///
/// Skip-slot cases (`const [, b]`, `const [a, ,]`) also need pattern-position
/// indexing: `TaintMeta.array_pattern_indices` carries the source-order
/// position of each binding so the rewrite picks `pd_args[index]` rather
/// than `pd_args[binding_offset]`.
#[test]
fn promise_all_destruct_per_index() {
    let findings = scan_fixture("promise_all_destruct");

    // Positive: line 17 sink reachable from req.body via index-1 binding.
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "promise_all_destruct_fp.ts",
            sink_line: 17,
            source_line: None,
        },
    );

    // Negative: line 16 binds `a` to the literal "ok"; pre-fix the scalar
    // union painted `a` with req.body's taint and produced a FP here.
    let leak = findings.iter().any(|f| {
        f.path.ends_with("promise_all_destruct_fp.ts")
            && f.line == 16
            && f.id.starts_with("taint-unsanitised-flow")
    });
    assert!(
        !leak,
        "destructure index-0 binding `a` must not carry req.body taint; got:\n{}",
        findings
            .iter()
            .filter(|f| f.path.ends_with("promise_all_destruct_fp.ts"))
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    // Skip-slot positives: only the index-aligned tainted bindings should fire.
    for sink_line in [24usize, 36] {
        assert_finding(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: "promise_all_skip_slots.ts",
                sink_line,
                source_line: None,
            },
        );
    }

    // Skip-slot negatives: lines 28 (`c` from `[, c]` of `[tainted, safe]`)
    // and 32 (`d` from `[d, ,]` of `[safe, tainted, "extra"]`) must NOT fire.
    for forbidden_line in [28usize, 32] {
        let leak = findings.iter().any(|f| {
            f.path.ends_with("promise_all_skip_slots.ts")
                && f.line == forbidden_line
                && f.id.starts_with("taint-unsanitised-flow")
        });
        assert!(
            !leak,
            "skip-slot binding at line {forbidden_line} must not carry req.body taint; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with("promise_all_skip_slots.ts"))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    // Python `asyncio.gather` destructure: `pattern_list` + `tuple_pattern`
    // share the same per-index rewrite as JS/TS arrays. Positives at lines
    // 32 / 40 / 50 (tainted-aligned bindings) must fire; negatives at lines
    // 33 / 41 / 51 (safe-aligned bindings) must NOT fire.
    for sink_line in [32usize, 40, 50] {
        assert_finding(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: "asyncio_gather_destruct_fp.py",
                sink_line,
                source_line: None,
            },
        );
    }
    for forbidden_line in [33usize, 41, 51] {
        let leak = findings.iter().any(|f| {
            f.path.ends_with("asyncio_gather_destruct_fp.py")
                && f.line == forbidden_line
                && f.id.starts_with("taint-unsanitised-flow")
        });
        assert!(
            !leak,
            "Python asyncio.gather binding at line {forbidden_line} must not carry request.args taint; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with("asyncio_gather_destruct_fp.py"))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    // Bare-array RHS destructure (`const [a, b] = [safe, tainted]`)
    // mirror of the Promise.all destructure precision, gated on
    // `info.call.callee.is_none()` so the combinator path is not
    // affected.  Each binding emits its own SSA op keyed on the
    // source-order RHS slot.
    for sink_line in [28usize, 36] {
        assert_finding(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: "bare_array_literal_destruct_fp.ts",
                sink_line,
                source_line: None,
            },
        );
    }
    for forbidden_line in [27usize, 37, 44] {
        let leak = findings.iter().any(|f| {
            f.path.ends_with("bare_array_literal_destruct_fp.ts")
                && f.line == forbidden_line
                && f.id.starts_with("taint-unsanitised-flow")
        });
        assert!(
            !leak,
            "JS/TS bare-array binding at line {forbidden_line} must not carry req.body taint; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with("bare_array_literal_destruct_fp.ts"))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    // Ruby parallel assignment `a, b = [array_literal]` now gets per-index
    // precision via the bare-array RHS rewrite at `src/ssa/lower.rs`.
    // Each binding emits its own SSA op keyed on its source-order RHS
    // slot — ident slots Assign the slot's value, literal slots emit
    // Const(None). Positives at handler lines 25 / 32 / 37 (tainted-
    // aligned bindings) must fire; negatives at 26 / 31 / 38 / 39
    // (literal-aligned bindings) must NOT fire.
    for sink_line in [23usize, 30, 35] {
        assert_finding(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: "ruby_parallel_assignment_fp.rb",
                sink_line,
                source_line: None,
            },
        );
    }
    for forbidden_line in [24usize, 29, 36, 37] {
        let leak = findings.iter().any(|f| {
            f.path.ends_with("ruby_parallel_assignment_fp.rb")
                && f.line == forbidden_line
                && f.id.starts_with("taint-unsanitised-flow")
        });
        assert!(
            !leak,
            "Ruby parallel assignment binding at line {forbidden_line} must not carry name taint; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with("ruby_parallel_assignment_fp.rb"))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    // Complex-slot bare-array RHS destructure (`const [a, b] =
    // [normalize(req.body.cmd), 'static']`).  The helper now classifies
    // call / binary / subscript / member access / template-string slots
    // as `Complex(inner_uses)` rather than bailing.  Each Complex slot
    // emits a slot-scoped `Assign` (or `Source` when the outer node
    // carries a Source label), so the literal-aligned binding is
    // correctly clean.  Positives at lines 32 / 39 / 46 / 54 / 62 fire;
    // negatives at lines 33 / 40 / 47 / 55 / 63 must NOT fire.
    for sink_line in [32usize, 39, 46, 54, 62] {
        assert_finding(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: "complex_slot_destruct_fp.ts",
                sink_line,
                source_line: None,
            },
        );
    }
    for forbidden_line in [33usize, 40, 47, 55, 63] {
        let leak = findings.iter().any(|f| {
            f.path.ends_with("complex_slot_destruct_fp.ts")
                && f.line == forbidden_line
                && f.id.starts_with("taint-unsanitised-flow")
        });
        assert!(
            !leak,
            "complex-slot literal binding at line {forbidden_line} must not carry req.body taint; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with("complex_slot_destruct_fp.ts"))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    // Per-slot Source classification: when two Complex slots sit next to
    // each other and ONLY one slot's subtree contains a Source-classified
    // member-expression, the safe Complex sibling stays slot-scoped instead
    // of inheriting the outer-node Source.  Pre-session 0047 the legacy
    // outer-node fallback painted both slots, producing a FP on the safe
    // sibling's binding.
    for sink_line in [27usize, 34, 41] {
        assert_finding(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: "complex_complex_per_slot_fp.ts",
                sink_line,
                source_line: None,
            },
        );
    }
    for forbidden_line in [28usize, 35, 42] {
        let leak = findings.iter().any(|f| {
            f.path.ends_with("complex_complex_per_slot_fp.ts")
                && f.line == forbidden_line
                && f.id.starts_with("taint-unsanitised-flow")
        });
        assert!(
            !leak,
            "safe Complex sibling at line {forbidden_line} must not inherit per-slot Source; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with("complex_complex_per_slot_fp.ts"))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    // Slot-scoped transitive taint: when the outer destructure node
    // carries a Source label AND another Complex slot's subtree classifies
    // as Source, the safe Complex sibling whose own subtree contains an
    // identifier bound to a tainted local (e.g.
    // `helper(tainted_local)` where `tainted_local = req.body.cmd`)
    // must still propagate the inner ident's taint through the slot-scoped
    // `Assign`.  Pre-session 0048 the kill arm emitted `Const(None)` which
    // dropped the transitive taint.
    for sink_line in [29usize, 30, 36] {
        assert_finding(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: "complex_transitive_taint_fp.ts",
                sink_line,
                source_line: None,
            },
        );
    }
    {
        let forbidden_line = 37usize;
        let leak = findings.iter().any(|f| {
            f.path.ends_with("complex_transitive_taint_fp.ts")
                && f.line == forbidden_line
                && f.id.starts_with("taint-unsanitised-flow")
        });
        assert!(
            !leak,
            "safe Complex sibling at line {forbidden_line} must not inherit outer Source; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with("complex_transitive_taint_fp.ts"))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Phase 03 recall-gap: `for await (const x of iter)` taints `x` from the
/// iterator (Web Streams / async-iterable request body).
#[test]
fn for_await_of_stream() {
    let findings = scan_fixture("for_await_of_stream");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "for_await_of_stream.ts",
            sink_line: 5,
            source_line: None,
        },
    );
}

/// Phase 03 re-entrancy guard: a 2-deep `.then` chain whose inner callback
/// awaits another promise.  Confirms the inline cache does not deadlock and
/// k=1 depth is still enforced.  Outer-level taint must still reach the sink
/// even when the inner level cannot recurse.
#[test]
fn promise_then_chain_reentrant() {
    let findings = scan_fixture("promise_then_chain");
    // The chain deliberately has two `.then` levels.  At k=1 the inner
    // `.then(inner)` cannot recurse, so the engine treats the inner
    // callback's body as opaque and propagates conservatively.  We only
    // assert the run does not panic and produces *some* finding for this
    // file (taint reaches the inner sink via the outer flow).
    let any = findings
        .iter()
        .any(|f| f.path.ends_with("promise_then_chain.ts"));
    assert!(
        any,
        "expected at least one finding from promise_then_chain.ts, got:\n{}",
        findings
            .iter()
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Phase 05 recall-gap: `import { readFile } from 'fs/promises'` →
/// `await readFile(req.body.path)` is a FILE_IO sink. The bare-name
/// `readFile` matcher only fires because the file's import table maps
/// the binding to `fs/promises`, satisfying the
/// `LabelGate::ImportedFromModule` gate.
#[test]
fn fs_promises_readfile() {
    let findings = scan_fixture("fs_promises/path_traversal_fs_promises_readfile.ts");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "path_traversal_fs_promises_readfile.ts",
            sink_line: 10,
            source_line: Some(9),
        },
    );
}

/// Phase 05 recall-gap: `await open(req.query.path, "r")` ─ same gate,
/// different fs/promises method.  Confirms the matcher list covers
/// `open` alongside `readFile`.
#[test]
fn fs_promises_open() {
    let findings = scan_fixture("fs_promises/path_traversal_fs_promises_open.ts");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "path_traversal_fs_promises_open.ts",
            sink_line: 10,
            source_line: Some(9),
        },
    );
}

/// Phase 05 recall-gap: the `node:` URL specifier flavour — `import {
/// writeFile } from 'node:fs/promises'`.  Both spellings must satisfy
/// the gate.
#[test]
fn fs_promises_node_import() {
    let findings = scan_fixture("fs_promises/path_traversal_node_fs_promises_import.ts");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "path_traversal_node_fs_promises_import.ts",
            sink_line: 10,
            source_line: Some(9),
        },
    );
}

/// Phase 05 recall-gap: namespace-import shape — `import * as fsp from
/// 'fs/promises'`.  `fsp.readFile(...)` must satisfy the gate via the
/// receiver-name path of the local-import view.
#[test]
fn fs_promises_namespace_import() {
    let findings = scan_fixture("fs_promises/path_traversal_fs_promises_namespace.ts");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "path_traversal_fs_promises_namespace.ts",
            sink_line: 11,
            source_line: Some(10),
        },
    );
}

/// Phase 05 recall-gap: CommonJS require shape — `const { readFile } =
/// require('fs/promises')`.  `extract_local_import_view` records the
/// destructured binding so the bare-name call still satisfies the gate.
#[test]
fn fs_promises_require_form() {
    let findings = scan_fixture("fs_promises/path_traversal_fs_promises_require.ts");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "path_traversal_fs_promises_require.ts",
            sink_line: 10,
            source_line: Some(9),
        },
    );
}

/// Phase 05 recall-gap: namespace-of-namespace alias —
/// `import * as fs from 'fs'; const fsp = fs.promises;`. The
/// promises-alias extension on `extract_local_import_view` adds
/// `fsp -> fs/promises` so `fsp.readFile(path)` satisfies the gate
/// without an explicit `import ... from 'fs/promises'` line.
#[test]
fn fs_promises_alias_form() {
    let findings = scan_fixture("fs_promises/path_traversal_fs_promises_alias.ts");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "path_traversal_fs_promises_alias.ts",
            sink_line: 14,
            source_line: Some(13),
        },
    );
}

/// Phase 05 recall-gap: CommonJS form of the alias shape —
/// `const fsp = require('fs').promises;`. Same gate as the ESM-import
/// alias above; promises-alias recognises the `.promises` projection on
/// the bare `require('fs')` call.
#[test]
fn fs_promises_alias_require_form() {
    let findings = scan_fixture("fs_promises/path_traversal_fs_promises_alias_require.ts");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "path_traversal_fs_promises_alias_require.ts",
            sink_line: 12,
            source_line: Some(11),
        },
    );
}

/// Phase 05 negative: a user-defined `readFile` (no import) must not
/// fire the gated FILE_IO sink.  The whole point of the import gate.
#[test]
fn fs_promises_safe_userfn() {
    let findings = scan_fixture("fs_promises/path_traversal_fs_promises_safe_userfn.ts");
    let leak = findings.iter().any(|f| {
        f.path
            .ends_with("path_traversal_fs_promises_safe_userfn.ts")
            && (f.id.starts_with("taint-unsanitised-flow")
                || f.id.starts_with("cfg-unguarded-sink"))
    });
    assert!(
        !leak,
        "user-defined readFile should not fire the fs/promises gate; got:\n{}",
        findings
            .iter()
            .filter(|f| f
                .path
                .ends_with("path_traversal_fs_promises_safe_userfn.ts"))
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Phase 06 recall-gap: React JSX `<div dangerouslySetInnerHTML={{__html:
/// x}} />`.  The CFG builder synthesises a sink call from the JSX
/// attribute, so the auto-seeded `input` formal flows into HTML_ESCAPE at
/// the `__html: input` value-span line.
#[test]
fn jsx_dangerous_html() {
    let findings = scan_fixture("jsx_dangerous_html");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "page.tsx",
            sink_line: 8,
            source_line: None,
        },
    );
    // Negative — `__html` is a string literal, no taint flows.
    let leak_literal = findings.iter().any(|f| {
        f.path.ends_with("page_safe_literal.tsx")
            && (f.id.starts_with("taint-unsanitised-flow")
                || f.id.starts_with("cfg-unguarded-sink"))
    });
    assert!(
        !leak_literal,
        "literal __html must not fire dangerouslySetInnerHTML; got:\n{}",
        findings
            .iter()
            .filter(|f| f.path.ends_with("page_safe_literal.tsx"))
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    // Negative — `__html: DOMPurify.sanitize(input)` is sanitized.
    let leak_indirect = findings.iter().any(|f| {
        f.path.ends_with("page_indirect.tsx")
            && (f.id.starts_with("taint-unsanitised-flow")
                || f.id.starts_with("cfg-unguarded-sink"))
    });
    assert!(
        !leak_indirect,
        "DOMPurify.sanitize-routed payload must not fire dangerouslySetInnerHTML; got:\n{}",
        findings
            .iter()
            .filter(|f| f.path.ends_with("page_indirect.tsx"))
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    // Negative — `__html: pipe(input, sanitizeHtml, DOMPurify.sanitize)` —
    // the fp-ts composition recogniser detects sanitizers in argument
    // position and suppresses the synthetic sink's argument-side flow.
    let leak_pipe = findings.iter().any(|f| {
        f.path.ends_with("page_pipe.tsx")
            && (f.id.starts_with("taint-unsanitised-flow")
                || f.id.starts_with("cfg-unguarded-sink"))
    });
    assert!(
        !leak_pipe,
        "pipe(...sanitizers) payload must not fire dangerouslySetInnerHTML; got:\n{}",
        findings
            .iter()
            .filter(|f| f.path.ends_with("page_pipe.tsx"))
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    // Positive (item 11) — JSX inside a ternary RHS branch.  The synthesis
    // hook in `lower_ternary_branch` reaches the `__html: input` value span
    // even though the wrapping arm short-circuits into the ternary diamond.
    let hits_ternary: Vec<&_> = findings
        .iter()
        .filter(|f| {
            f.path.ends_with("page_ternary.tsx")
                && (f.id.starts_with("taint-unsanitised-flow")
                    || f.id.starts_with("cfg-unguarded-sink"))
        })
        .collect();
    assert!(
        !hits_ternary.is_empty(),
        "ternary-branch dangerouslySetInnerHTML must fire a sink; got nothing for page_ternary.tsx"
    );
}

/// Phase 07 recall-gap: ORM query-builder raw-SQL escape hatches.
///
/// Coverage:
///   - Drizzle `sql.raw(x)` and tagged-template `sql\`...\`` shapes
///     (leading-id `ImportedFromModule(&["drizzle-orm"])` gate)
///   - Sequelize `sequelize.literal(x)` via receiver-type
///     qualification (`TypeKind::Sequelize` → `Sequelize.literal`)
///   - TypeORM `repo.query(...)` via receiver-type qualification
///     (`TypeKind::TypeOrmRepo` → `TypeOrmRepo.query`)
///   - Knex `db.whereRaw(...)` via the new file-level
///     `FileImportsModule(&["knex"])` gate
///
/// Negatives:
///   - parameterised TypeORM `repo.query("...", [const])` stays silent
///   - bare `whereRaw` / `literal` calls in a file without ORM imports
#[test]
fn orm_builders() {
    let findings = scan_fixture("orm_builders");

    // (file, sink_line) — sink_line points at the actual SQL builder call.
    // `sqli_typeorm_query.ts` previously asserted line 17 (`res.json(rows)`)
    // and was satisfied by a coincidental XSS finding; the real
    // `repo.query(...)` sink lives on line 16, and the cap-aware assertion
    // below pins the SQL_QUERY capability so an XSS regression cannot mask
    // a missing receiver-type-qualified ORM rule.
    let positives = [
        ("sqli_drizzle_sql_raw.ts", 13usize),
        ("sqli_drizzle_tagged_template.ts", 14usize),
        ("sqli_sequelize_literal.ts", 14usize),
        ("sqli_typeorm_query.ts", 16usize),
        ("sqli_knex_where_raw.ts", 15usize),
        ("sqli_mikroorm_execute.ts", 13usize),
    ];
    for (file, sink_line) in positives {
        assert_finding_with_cap(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: file,
                sink_line,
                source_line: None,
            },
            Cap::SQL_QUERY.bits(),
        );
    }

    let negatives = [
        "sqli_typeorm_safe_parameterized.ts",
        "sqli_no_orm_import_safe.ts",
        "sqli_knex_type_only_safe.ts",
    ];
    for file in negatives {
        let leak = findings.iter().any(|f| {
            f.path.ends_with(file)
                && (f.id.starts_with("taint-unsanitised-flow")
                    || f.id.starts_with("cfg-unguarded-sink"))
                && f.evidence
                    .as_ref()
                    .map(|e| (e.sink_caps & Cap::SQL_QUERY.bits()) != 0)
                    .unwrap_or(false)
        });
        assert!(
            !leak,
            "ORM negative fixture {file} must not fire SQL_QUERY; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Phase 08 recall-gap: SSRF URL-builder shapes.
///
/// Coverage:
///   - `new URL(taintedPath)` propagates the path arg's taint into the
///     constructed URL value (no label rule, no summary — covered by the
///     URL-constructor pass added in Phase 08).
///   - `u.searchParams.set(k, taintedV)` / `.append(...)` taints the
///     receiver URL via the searchParams alias rule.
///   - `fetch({ url: taintedUrl, ... })` flows through the destination-
///     aware filter on the SSRF gate.
///   - `fetch(target)` where `target: URL` carries SSA-level
///     TypeKind::Url and the constructor-propagated taint.
///
/// Negative:
///   - `new URL(req.body.path, "https://api.cal.com")` — the literal
///     base anchors an origin-locked StringFact prefix that
///     `is_string_safe_for_ssrf` honours, so the SSRF stays silent.
#[test]
fn ssrf_url_builders() {
    let findings = scan_fixture("ssrf_url_builders");

    let positives = [
        ("ssrf_new_url.ts", 12usize),
        ("ssrf_searchparams_set.ts", 13usize),
        ("ssrf_searchparams_append.ts", 12usize),
        ("ssrf_fetch_object_form.ts", 11usize),
        ("ssrf_fetch_url_typed_arg.ts", 13usize),
        ("ssrf_fetch_object_shorthand.ts", 13usize),
        ("ssrf_fetch_object_shorthand.ts", 19usize),
    ];
    for (file, sink_line) in positives {
        assert_finding_with_cap(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: file,
                sink_line,
                source_line: None,
            },
            Cap::SSRF.bits(),
        );
    }

    // Negative: origin-locked `new URL(path, "https://api.cal.com")` must
    // not fire SSRF — the abstract-string prefix-lock suppresses it.
    let negative = "ssrf_url_origin_locked.ts";
    let leak = findings.iter().any(|f| {
        f.path.ends_with(negative)
            && f.evidence
                .as_ref()
                .map(|e| (e.sink_caps & Cap::SSRF.bits()) != 0)
                .unwrap_or(false)
            && (f.id.starts_with("taint-unsanitised-flow")
                || f.id.starts_with("cfg-unguarded-sink"))
    });
    assert!(
        !leak,
        "origin-locked URL must not fire SSRF; got:\n{}",
        findings
            .iter()
            .filter(|f| f.path.ends_with(negative))
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Phase 14 recall-gap: cross-language SSRF + URL-builder coverage.
///
/// Mirrors `ssrf_url_builders` (JS/TS) for Python, Java, Rust, Go, Ruby,
/// PHP. Each language carries:
///
///   * positive — a tainted source flowing into the language's
///     canonical HTTP client sink, asserting `Cap::SSRF` fires.
///   * origin-locked negative — a `(literal_base, tainted_path)` URL
///     builder shape; the abstract-string prefix lock honoured by
///     `is_string_safe_for_ssrf` suppresses the SSRF sink.
///   * search-params positive — a tainted URL passed positionally to
///     a Phase 14-added sink (`OkHttpClient.newCall`,
///     `\GuzzleHttp\Client::request`, etc.) so the new label rules
///     see real exercise alongside the existing flat sinks.
#[test]
fn ssrf_cross_language() {
    let findings = scan_fixture("ssrf");

    let positives = [
        // Python — tainted full URL flowing into requests.get / request.
        "ssrf_py_positive.py",
        "ssrf_py_search_params.py",
        // Java — HttpClient.send + OkHttpClient.newCall (Phase 14 sink).
        "SsrfJavaPositive.java",
        "SsrfJavaSearchParams.java",
        // Rust — reqwest::get + Client::new.get (chained verb-on-instance).
        "ssrf_rs_positive.rs",
        "ssrf_rs_search_params.rs",
        // Go — http.Get + http.NewRequest.
        "ssrf_go_positive.go",
        "ssrf_go_search_params.go",
        // Ruby — Net::HTTP.get + Faraday.get (Phase 14 sink).
        "ssrf_rb_positive.rb",
        "ssrf_rb_search_params.rb",
        // Ruby Faraday.new(url: tainted) construction-time SSRF and
        // Net::HTTP.start(host, port, proxy_addr: tainted) proxy-tainted
        // Destination gates added in the Phase 14 follow-up.
        "ssrf_rb_faraday_new.rb",
        "ssrf_rb_net_http_proxy.rb",
        // PHP — curl_exec via curl_setopt CURLOPT_URL gate (Phase 14)
        // + Guzzle Client::request (Phase 14 sink).
        "ssrf_php_positive.php",
        "ssrf_php_search_params.php",
    ];
    for file in positives {
        let hit = findings.iter().any(|f| {
            f.path.ends_with(file)
                && f.evidence
                    .as_ref()
                    .map(|e| (e.sink_caps & Cap::SSRF.bits()) != 0)
                    .unwrap_or(false)
                && (f.id.starts_with("taint-unsanitised-flow")
                    || f.id.starts_with("cfg-unguarded-sink"))
        });
        assert!(
            hit,
            "SSRF expected to fire on {file}; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    let negatives = [
        "ssrf_py_origin_locked.py",
        "SsrfJavaOriginLocked.java",
        "ssrf_rs_origin_locked.rs",
        "ssrf_rs_origin_locked_const_fmt.rs",
        "ssrf_go_origin_locked.go",
        "ssrf_rb_origin_locked.rb",
        "ssrf_rb_origin_locked_interp.rb",
        "ssrf_php_origin_locked.php",
    ];
    for file in negatives {
        let leak = findings.iter().any(|f| {
            f.path.ends_with(file)
                && f.evidence
                    .as_ref()
                    .map(|e| (e.sink_caps & Cap::SSRF.bits()) != 0)
                    .unwrap_or(false)
                && (f.id.starts_with("taint-unsanitised-flow")
                    || f.id.starts_with("cfg-unguarded-sink"))
        });
        assert!(
            !leak,
            "origin-locked SSRF must stay silent on {file}; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Phase 15 recall-gap: cross-language ORM and raw-SQL coverage.
///
/// Mirrors `orm_builders` (JS/TS) for Python, Java, Ruby, Go, PHP.
/// Each language carries:
///
///   * positive raw-string concat — tainted user input concatenated
///     into the SQL string flowing into the language's canonical
///     SQL_QUERY sink.
///   * positive interpolation — same shape but using language-native
///     interpolation (Python f-string inside `text(...)`, Java
///     `String.format`, Ruby `"#{...}"`, Go `fmt.Sprintf`, PHP
///     `"$var"`).
///   * negative parameterised — the parameterised API form with
///     literal SQL template + constant bind args, mirroring phase
///     07's safe-parameterised approach.
#[test]
fn orm_xlang() {
    let findings = scan_fixture("sqli_xlang");

    let positives = [
        // (file, sink_line)
        ("sqli_py_psycopg2_concat.py", 16usize),
        ("sqli_py_sqlalchemy_text_fstring.py", 18usize),
        ("SqliJavaConcat.java", 18usize),
        ("SqliJavaHibernateNative.java", 14usize),
        ("SqliJavaHibernateNamedSession.java", 19usize),
        ("SqliJavaHibernateChainedSession.java", 23usize),
        ("sqli_rb_concat.rb", 8usize),
        ("sqli_rb_where_interp.rb", 9usize),
        ("sqli_go_concat.go", 14usize),
        ("sqli_go_gorm_raw.go", 20usize),
        ("sqli_go_gorm_raw_named.go", 28usize),
        ("sqli_py_django_qs_bound.py", 14usize),
        ("sqli_py_django_qs_bare.py", 16usize),
        ("sqli_php_pdo_concat.php", 9usize),
        ("sqli_php_doctrine_interp.php", 10usize),
    ];
    for (file, sink_line) in positives {
        assert_finding_with_cap(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: file,
                sink_line,
                source_line: None,
            },
            Cap::SQL_QUERY.bits(),
        );
    }

    let negatives = [
        "sqli_py_param_safe.py",
        // Phase 15 deferred-fix: tainted bind args at arg 1 of
        // `cursor.execute("SELECT ... WHERE x = %s", (tainted,))` must
        // stay silent on SQL_QUERY because `payload_args = &[0]` on the
        // Destination gate restricts the sink scan to arg 0.
        "sqli_py_param_tainted_binds.py",
        "SqliJavaParamSafe.java",
        // Phase 15 deferred-fix (Java): tainted `setParameter` bind
        // value on a constant `entityManager.createQuery(...)` template
        // must stay silent on SQL_QUERY.  Mirrors the Python tainted-
        // binds shape; the Java Destination gate on the createQuery
        // family carries `payload_args = &[0]`.
        "SqliJavaParamTaintedBinds.java",
        "sqli_rb_param_safe.rb",
        "sqli_go_param_safe.go",
        // Phase 15 deferred-fix (Go): tainted bind value at arg 2 of
        // `db.QueryContext(ctx, sql, tainted)` must stay silent.  The
        // Destination gate on `db.QueryContext` carries
        // `payload_args = &[1]`, restricting the sink scan to the SQL
        // string at arg 1.
        "sqli_go_param_tainted_binds.go",
        "sqli_php_param_safe.php",
    ];
    for file in negatives {
        let leak = findings.iter().any(|f| {
            f.path.ends_with(file)
                && f.evidence
                    .as_ref()
                    .map(|e| (e.sink_caps & Cap::SQL_QUERY.bits()) != 0)
                    .unwrap_or(false)
                && (f.id.starts_with("taint-unsanitised-flow")
                    || f.id.starts_with("cfg-unguarded-sink"))
        });
        assert!(
            !leak,
            "parameterised SQLi negative {file} must stay silent on SQL_QUERY; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Phase 09 recall-gap: cross-package IPA via FuncKey namespace
/// resolution.  `unsafeHandler` calls `escapeHtmlNoop` (a passthrough
/// imported from `@scope/util/sanitize`); the engine sees the imported
/// callee's SSA summary via step 0.7 of `resolve_callee_full` and
/// therefore propagates `req.query.x` taint into `res.send` on line 7.
/// `safeHandler` calls `stripTags` (a real `replace`-based sanitizer
/// imported from `@scope/util/strip`) and must stay silent.
#[test]
fn cross_package_ipa() {
    let findings = scan_fixture("cross_package_ipa");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "handler.ts",
            sink_line: 7,
            source_line: Some(5),
        },
    );
    let safe_hit = findings.iter().any(|f| {
        f.id.starts_with("taint-unsanitised-flow")
            && f.path.ends_with("handler.ts")
            && f.line == 13
    });
    assert!(
        !safe_hit,
        "cross-package sanitizer fixture must stay silent at handler.ts:13; got:\n{}",
        findings
            .iter()
            .filter(|f| f.path.ends_with("handler.ts"))
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Phase 10 recall-gap: Next.js entry-point detection.  Coverage:
///   - App Router POST handler at `app/api/users/route.ts`: the first
///     formal is typed as `TypeKind::Request`, so `await req.json()`
///     surfaces as a SQL_QUERY sink at the `db.query(body)` call.
///   - File-level `'use server'` directive
///     (`nextjs_server_action.ts`, `nextjs_use_server_directive.ts`):
///     every exported function's formals are seeded as Source taint
///     at SSA entry.
///   - Function-level `'use server'`
///     (`nextjs_use_server_function_level.ts`): only the directive-
///     bearing function is treated as a server action.
///   - `<form action={fn}>` JSX binding (`nextjs_form_action.tsx`):
///     the named callee is tagged `EntryKind::FormAction` and its
///     first formal is seeded as adversary input.
///   - `next/headers` `cookies()` import-gated source: the gated rule
///     fires only when `cookies` is bound from `next/headers`.
#[test]
fn nextjs_entrypoints() {
    let findings = scan_fixture("nextjs_entrypoints");

    // Each fixture asserts the SQL sink fires.
    let positives = [
        ("route.ts", 11usize),
        ("nextjs_server_action.ts", 11usize),
        ("nextjs_use_server_directive.ts", 9usize),
        ("nextjs_use_server_function_level.ts", 8usize),
        ("nextjs_form_action.tsx", 10usize),
        ("nextjs_cookies_source.ts", 12usize),
    ];
    for (file, sink_line) in positives {
        assert_finding(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: file,
                sink_line,
                source_line: None,
            },
        );
    }
}

/// Phase 13 recall-gap (cross-language path traversal).  Five
/// languages, one positive + one sanitized fixture each, exercising the
/// new `Path.read_text` (Python), `Files.readAllBytes` (Java),
/// `tokio::fs::read` (Rust), `os.ReadFile` (Go), and `File.write`
/// (Ruby) FILE_IO sinks added in Phase 13.  Sanitized fixtures
/// canonicalise the path through the language-native sanitiser
/// (`Path.resolve` / `Path.normalize` / `PathBuf::canonicalize` /
/// `filepath.Clean` / `Pathname#cleanpath`) and demonstrate the safe
/// pattern by structuring the call chain so no FILE_IO sink reaches the
/// canonical value, keeping the fixture silent.
#[test]
fn path_traversal_xlang() {
    let positives = [
        // (file, sink_line, source_line)
        ("path_traversal.py", 12usize, Some(11usize)),
        ("PathTraversal.java", 16, Some(15)),
        ("path_traversal.rs", 22, Some(21)),
        ("path_traversal.go", 14, Some(13)),
        ("path_traversal.rb", 7, Some(6)),
    ];
    for (file, sink_line, source_line) in positives {
        let findings = scan_fixture(&format!("path_traversal/{file}"));
        assert_finding_with_cap(
            &findings,
            ExpectedFinding {
                rule_id: "taint-unsanitised-flow",
                file_suffix: file,
                sink_line,
                source_line,
            },
            Cap::FILE_IO.bits(),
        );
    }

    let negatives = [
        "path_traversal_safe.py",
        "PathTraversalSafe.java",
        "path_traversal_safe.rs",
        "path_traversal_safe.go",
        "path_traversal_safe.rb",
    ];
    for file in negatives {
        let findings = scan_fixture(&format!("path_traversal/{file}"));
        let leak = findings.iter().any(|f| {
            f.path.ends_with(file)
                && (f.id.starts_with("taint-unsanitised-flow")
                    || f.id.starts_with("cfg-unguarded-sink"))
        });
        assert!(
            !leak,
            "path_traversal sanitized fixture {file} must stay silent; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Phase 16 recall-gap: cross-language framework entry-point detection.
///
/// One fixture per framework, each takes a request input (function-formal
/// or path-captured kwarg) and pipes it to a language-native sink.  Every
/// fixture must fire the expected sink with the request parameter as
/// Source via the entry-kind seeding policy in `taint/ssa_transfer/mod.rs`.
///
/// The Spring fixture composes with phase 15 (Hibernate
/// `entityManager.createNativeQuery`), proving cross-phase composition
/// holds across languages.
#[test]
fn entry_points_xlang() {
    let findings = scan_fixture("entry_points_xlang");

    let positives = [
        "django_view.py",
        "fastapi_route.py",
        "flask_route.py",
        "spring_controller.java",
        "rails_action.rb",
        "axum_handler.rs",
        "actix_handler.rs",
        "gin_handler.go",
        "express_route.js",
    ];
    for file in positives {
        let hit = findings.iter().any(|f| {
            f.path.ends_with(file)
                && (f.id.starts_with("taint-unsanitised-flow")
                    || f.id.starts_with("cfg-unguarded-sink"))
        });
        assert!(
            hit,
            "Phase 16 entry-point fixture {file} must fire a taint sink; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Rust entry-kind seeding precision: typed extractor formals
/// (`Query<T>`, `Json<T>`, `Form<T>`, `Path<T>`, `web::*<T>`) get
/// painted as `Source(UserInput)`, while denylist DI handles
/// (`State<T>`, `Extension<T>`, ...) do not.  Without this guard, the
/// scoped-lowering lift for Rust handlers would FP-fire every
/// database / shared-state sink consuming a pool handle.  The
/// positive shape asserts the rule_id is specifically
/// `taint-unsanitised-flow` (not `cfg-unguarded-sink`), so a future
/// regression that drops entry-kind seeding is forcing-function
/// caught.
#[test]
fn rust_entry_kind_typed_extractor_seeding() {
    let findings = scan_fixture("entry_points_xlang_rust");
    let positives = [
        ("axum_query_typed_extractor.rs", 12usize),
        ("actix_path_typed_extractor.rs", 11usize),
    ];
    for (file, sink_line) in positives {
        let hit = findings.iter().any(|f| {
            f.path.ends_with(file)
                && f.id.starts_with("taint-unsanitised-flow")
                && f.line == sink_line
        });
        assert!(
            hit,
            "Rust typed-extractor handler {file}:{sink_line} must fire \
             `taint-unsanitised-flow`; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    // Negative: State<Arc<DbPool>> formals must not produce
    // taint-unsanitised-flow findings.  cfg-unguarded-sink is fine
    // — that is the pre-existing structural backup, not a seeding
    // claim against the formal.
    let state_taint_findings: Vec<&_> = findings
        .iter()
        .filter(|f| {
            f.path.ends_with("axum_state_denylist.rs")
                && f.id.starts_with("taint-unsanitised-flow")
        })
        .collect();
    assert!(
        state_taint_findings.is_empty(),
        "State<DbPool> formals must not be painted as Source; got:\n{}",
        state_taint_findings
            .iter()
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Python entry-kind seeding precision for `FlaskRoute`: path-bound
/// formals (`@app.route("/u/<name>")` + `def view(name):`) get painted
/// as `Source(UserInput)`, while routes without path captures stay
/// un-seeded.  Without per-formal route-capture gating, Python handlers
/// fell back to `cfg-unguarded-sink` for path-bound flows.  The
/// positive shape asserts the rule_id is specifically
/// `taint-unsanitised-flow` (not `cfg-unguarded-sink`), so a future
/// regression that drops entry-kind seeding is forcing-function
/// caught.  The negative shape pins the absence of taint findings on a
/// no-capture route (no formals, no seed, no flow).
#[test]
fn python_flask_route_path_capture_seeding() {
    let findings = scan_fixture("entry_points_xlang_python");
    let positives = [
        ("flask_path_capture.py", 14usize),
        ("flask_converter_capture.py", 14usize),
    ];
    for (file, sink_line) in positives {
        let hit = findings.iter().any(|f| {
            f.path.ends_with(file)
                && f.id.starts_with("taint-unsanitised-flow")
                && f.line == sink_line
        });
        assert!(
            hit,
            "Python Flask path-capture handler {file}:{sink_line} must fire \
             `taint-unsanitised-flow`; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    // Negative: a Flask route with no path captures and a literal
    // sink argument must not surface `taint-unsanitised-flow`.
    let no_capture_taint: Vec<&_> = findings
        .iter()
        .filter(|f| {
            f.path.ends_with("flask_no_capture.py")
                && f.id.starts_with("taint-unsanitised-flow")
        })
        .collect();
    assert!(
        no_capture_taint.is_empty(),
        "Flask route without path captures must not paint formals as Source; got:\n{}",
        no_capture_taint
            .iter()
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Python FastAPI entry-kind seeding precision for `FastApiRoute`:
/// path-bound formals from `{name}` brace-segment captures
/// (`@app.get("/items/{item_id}")` + `def read_item(item_id: str):`)
/// AND Annotated typed extractors (`q: Annotated[str, Query()]`) get
/// painted as `Source(UserInput)`. Formals that carry a `Depends(...)`
/// default or a non-extractor type annotation (`db: Session`,
/// `request: Request`) stay un-seeded. Without per-formal gating,
/// FastAPI handlers fell back to `cfg-unguarded-sink` for path-bound
/// flows. The positive shapes assert the rule_id is specifically
/// `taint-unsanitised-flow`, so a future regression that drops
/// entry-kind seeding is forcing-function caught. The negative shape
/// pins the absence of `taint-unsanitised-flow` on a DI-only handler.
#[test]
fn python_fastapi_route_per_formal_seeding() {
    let findings = scan_fixture("entry_points_xlang_python_fastapi");
    let positives = [
        ("fastapi_path_capture.py", 18usize),
        ("fastapi_annotated_query.py", 17usize),
    ];
    for (file, sink_line) in positives {
        let hit = findings.iter().any(|f| {
            f.path.ends_with(file)
                && f.id.starts_with("taint-unsanitised-flow")
                && f.line == sink_line
        });
        assert!(
            hit,
            "Python FastAPI handler {file}:{sink_line} must fire \
             `taint-unsanitised-flow`; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    let depends_taint: Vec<&_> = findings
        .iter()
        .filter(|f| {
            f.path.ends_with("fastapi_depends_denylist.py")
                && f.id.starts_with("taint-unsanitised-flow")
        })
        .collect();
    assert!(
        depends_taint.is_empty(),
        "FastAPI Depends(...) DI handle must not be painted as Source; got:\n{}",
        depends_taint
            .iter()
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Ruby Sinatra entry-kind seeding precision for `SinatraRoute`:
/// path-bound block formals (`get "/u/:name" do |name| ... end`)
/// get painted as `Source(UserInput)`, while routes without path
/// captures stay un-seeded. Without per-formal route-capture
/// gating, Sinatra handlers fell back to `cfg-unguarded-sink` for
/// path-bound flows. The positive shape asserts the rule_id is
/// specifically `taint-unsanitised-flow`, so a future regression
/// that drops entry-kind seeding is forcing-function caught. The
/// negative shape pins the absence of taint findings on a
/// no-capture route (no block formals, no seed, no flow).
#[test]
fn ruby_sinatra_route_path_capture_seeding() {
    let findings = scan_fixture("entry_points_xlang_ruby");
    let positives = [
        ("sinatra_path_capture.rb", 9usize),
        ("sinatra_multi_capture.rb", 8usize),
    ];
    for (file, sink_line) in positives {
        let hit = findings.iter().any(|f| {
            f.path.ends_with(file)
                && f.id.starts_with("taint-unsanitised-flow")
                && f.line == sink_line
        });
        assert!(
            hit,
            "Ruby Sinatra path-capture handler {file}:{sink_line} must fire \
             `taint-unsanitised-flow`; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    let no_capture_taint: Vec<&_> = findings
        .iter()
        .filter(|f| {
            f.path.ends_with("sinatra_no_capture.rb")
                && f.id.starts_with("taint-unsanitised-flow")
        })
        .collect();
    assert!(
        no_capture_taint.is_empty(),
        "Sinatra route without path captures must not paint formals as Source; got:\n{}",
        no_capture_taint
            .iter()
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Go entry-kind precision: `GinRoute` (`*gin.Context`,
/// `echo.Context`, `*fiber.Ctx`, `iris.Context`) and `GoNetHttp`
/// (`(w http.ResponseWriter, r *http.Request)`) handlers route
/// adversary bytes through access-path label rules
/// (`c.Query`, `c.Param`, `c.PostForm`, `r.URL.Query`,
/// `r.FormValue`, `r.Header.Get`, ...) rather than via flat
/// formal seeding. Same precedent as the Express
/// `seed_at_all=false` arm: painting the bare `c` / `r` object
/// as `Source(Cap::all())` re-fires excluded lifecycle methods
/// (`c.AbortWithStatus`, `r.Context()`, etc.) as structural
/// sinks. The positive shapes assert the rule_id is specifically
/// `taint-unsanitised-flow` (not the OR-cfg-unguarded-sink path
/// the cross-language `entry_points_xlang` test accepts), so a
/// future regression that mis-classifies access paths is
/// forcing-function caught.
#[test]
fn go_entry_kind_label_rules_carry_request() {
    let findings = scan_fixture("entry_points_xlang");
    let positives = [
        ("gin_handler.go", 24usize),
        ("net_http_handler.go", 21usize),
    ];
    for (file, sink_line) in positives {
        let hit = findings.iter().any(|f| {
            f.path.ends_with(file)
                && f.id.starts_with("taint-unsanitised-flow")
                && f.line == sink_line
        });
        assert!(
            hit,
            "Go handler {file}:{sink_line} must fire \
             `taint-unsanitised-flow` via access-path label rules; got:\n{}",
            findings
                .iter()
                .filter(|f| f.path.ends_with(file))
                .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Phase 11 + 17 acceptance: every per-target baseline JSON in
/// `tests/recall_targets/` (Phase 11 JS targets) and
/// `tests/recall_targets/xlang/<lang>/` (Phase 17 cross-lang targets)
/// exists, parses via `serde_json`, and every finding entry carries
/// a `verdict: "TP" | "FP" | "needs_review"` label. Marked `#[ignore]`
/// because `cargo test --release` should not require a populated
/// baseline directory on a clean clone — the `validate_recall.sh`
/// runbook is the authoritative way to refresh these. Run explicitly
/// with `cargo test --release --test recall_gaps --
/// --ignored validate_real_world_targets`.
#[test]
#[ignore]
fn validate_real_world_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/recall_targets");

    // Phase 11 JS targets — ship at the top level.
    let js_targets = ["cal_com", "vercel_commerce", "shadcn_examples", "blitz_apps"];
    let mut paths: Vec<std::path::PathBuf> =
        js_targets.iter().map(|t| root.join(format!("{t}.json"))).collect();

    // Phase 17 cross-lang targets — under `xlang/<lang>/<target>.json`.
    // Derived from filesystem inspection so adding a new lang/target only
    // requires dropping the JSON file under `tests/recall_targets/xlang/`.
    let xlang_root = root.join("xlang");
    if let Ok(entries) = std::fs::read_dir(&xlang_root) {
        let mut lang_dirs: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        lang_dirs.sort();
        for lang_dir in lang_dirs {
            let mut json_paths: Vec<std::path::PathBuf> = std::fs::read_dir(&lang_dir)
                .unwrap_or_else(|e| panic!("read xlang dir {}: {e}", lang_dir.display()))
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect();
            json_paths.sort();
            paths.extend(json_paths);
        }
    }

    for path in &paths {
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read baseline {}: {e}", path.display()));
        let value: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse baseline {}: {e}", path.display()));
        let obj = value
            .as_object()
            .unwrap_or_else(|| panic!("baseline {} must be a JSON object", path.display()));
        for key in ["target", "clone_url", "captured_against", "captured_on", "pinned_commit"] {
            assert!(
                obj.contains_key(key),
                "baseline {} must record `{key}`",
                path.display()
            );
        }
        let findings = obj
            .get("findings")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("baseline {} must record `findings: []`", path.display()));
        for (i, f) in findings.iter().enumerate() {
            let verdict = f
                .get("verdict")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "baseline {} finding {i} missing `verdict`",
                        path.display()
                    )
                });
            assert!(
                matches!(verdict, "TP" | "FP" | "needs_review"),
                "baseline {} finding {i} has invalid verdict {verdict:?} (must be TP|FP|needs_review)",
                path.display()
            );
        }
    }
}

#[test]
fn baseline_loads() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/recall_gaps_baseline.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read baseline {}: {e}", path.display()));
    let value: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse baseline {}: {e}", path.display()));
    assert!(value.is_object(), "baseline must be a JSON object");
    assert!(
        value.get("recall_gaps_tests").is_some(),
        "baseline must record `recall_gaps_tests`"
    );
    assert!(
        value.get("corpus_finding_lines").is_some(),
        "baseline must record `corpus_finding_lines`"
    );
    let corpus = value.get("corpus_finding_lines").unwrap();
    let rule_full = corpus.get("rule_id_full").unwrap_or_else(|| {
        panic!(
            "baseline must record `corpus_finding_lines.rule_id_full` (per-rule snapshot, not just top-15) so phases 03-11 can prove rule-level non-regression"
        )
    });
    let map = rule_full
        .as_object()
        .expect("`rule_id_full` must be a JSON object mapping rule_id → count");
    let distinct = corpus
        .get("rule_id_distinct")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    assert_eq!(
        map.len(),
        distinct,
        "rule_id_full ({}) must cover every distinct rule_id ({})",
        map.len(),
        distinct
    );
}
