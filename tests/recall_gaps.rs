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
fn async_await() {
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

/// Phase 03 recall-gap: `.then(cb)` propagates the receiver Promise's
/// resolved value into the callback's first parameter.  The taint trace
/// surfaces at the `.then(cb)` call site via the engine's callback-pattern
/// emission (`source_to_callback` paired with `cb`'s `param_to_sink`).
#[test]
fn promise_then_callback() {
    let findings = scan_fixture("promise_then_callback");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "promise_then_callback.ts",
            sink_line: 12,
            source_line: Some(7),
        },
    );
}

/// Phase 03 recall-gap: `Promise.all([...])` returns a value carrying the
/// union of element taints; `p.then(cb)` then exposes it to the sink at
/// the `.then` call site via the callback-pattern emission.
#[test]
fn promise_all_taint() {
    let findings = scan_fixture("promise_all_taint");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "promise_all_taint.ts",
            sink_line: 11,
            source_line: None,
        },
    );
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
/// Coverage:
///   - Drizzle `sql.raw(x)` and tagged-template `sql\`...\`` shapes
///     (leading-id `ImportedFromModule(&["drizzle-orm"])` gate)
///   - Sequelize `sequelize.literal(x)` via receiver-type
///     qualification (`TypeKind::Sequelize` → `Sequelize.literal`)
///   - TypeORM `repo.query(...)` via receiver-type qualification
///     (`TypeKind::TypeOrmRepo` → `TypeOrmRepo.query`)
///   - Knex `db.whereRaw(...)` via the new file-level
///     `FileImportsModule(&["knex"])` gate
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
