//! Audit suite for Phases 1–5 of the typed call-graph devirtualisation
//! pipeline (see `docs/typed-call-graph-prompt.md` and
//! `docs/typed-call-graph-phase6-and-audit-prompt.md`).
//!
//! The lower-level Phase 1 / 2 / 3 unit tests under
//! `src/callgraph.rs::tests` and `src/taint/tests.rs` already prove the
//! per-module API behaviour.  These tests pin the *integration*
//! invariants, that the pipeline as a whole still produces the right
//! `typed_call_receivers` entries on real source code, that the call
//! graph picks the receiver-typed candidate at edge-insertion time,
//! and that today's behaviour is preserved on every negative /
//! regression shape.

mod common;

use nyx_scanner::ast::extract_all_summaries_from_bytes;
use nyx_scanner::callgraph::build_call_graph;
use nyx_scanner::summary::{GlobalSummaries, ssa_summary::SsaFuncSummary};
use nyx_scanner::symbol::{FuncKey, Lang};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

use common::test_config;

// ─────────────────────────────────────────────────────────────────────
//  Pipeline harness
// ─────────────────────────────────────────────────────────────────────

/// Source fragment + namespace pair for the harness below.
struct File<'a> {
    namespace: &'a str,
    bytes: &'a [u8],
}

/// Run the pass-1 extraction pipeline on a synthetic file set and merge
/// every artifact into one [`GlobalSummaries`].  Mirrors the production
/// pipeline up to (and including) `merge_summaries` / `insert_ssa`,
/// which is the input Phase 3 (`build_call_graph`) consumes.
///
/// The caller is responsible for picking absolute paths whose `Path`
/// representation matches the namespace it expects on the resulting
/// [`FuncKey`]s, `extract_all_summaries_from_bytes` writes the raw
/// `path` into `FuncSummary::file_path` which then flows through to
/// `FuncKey::namespace` after `merge_summaries`.
fn pipeline_global_summaries(files: &[File<'_>]) -> GlobalSummaries {
    let cfg = test_config(AnalysisMode::Taint);

    let mut all_func: Vec<nyx_scanner::summary::FuncSummary> = Vec::new();
    let mut all_ssa: Vec<(FuncKey, SsaFuncSummary)> = Vec::new();
    for f in files {
        let path = Path::new(f.namespace);
        let (func, ssa, _bodies, _auth, _cpi) =
            extract_all_summaries_from_bytes(f.bytes, path, &cfg, None)
                .expect("extract_all_summaries_from_bytes must succeed");
        all_func.extend(func);
        all_ssa.extend(ssa);
    }

    let mut gs = nyx_scanner::summary::merge_summaries(all_func, None);
    for (k, s) in all_ssa {
        gs.insert_ssa(k, s);
    }
    gs
}

/// Look up an SSA summary whose key has the given `name` and
/// `container` (any namespace / arity).  Returns `None` if no match.
fn find_ssa<'a>(
    gs: &'a GlobalSummaries,
    name: &str,
    container: &str,
) -> Option<&'a SsaFuncSummary> {
    gs.snapshot_ssa()
        .iter()
        .find(|(k, _)| k.name == name && k.container == container)
        .map(|(_, s)| s)
}

// ─────────────────────────────────────────────────────────────────────
//  A.2.1, End-to-end pipeline test
// ─────────────────────────────────────────────────────────────────────

/// Pipeline test: Java caller invokes a method on a constructor-typed
/// receiver.  Asserts both the SSA-extraction half (Phase 2 populates
/// `typed_call_receivers` with the expected container) and the call-
/// graph half (Phase 3 routes the indirect method-call edge through
/// the typed receiver to `FileHandle::close`, not the same-name
/// `Cache::close` overload).
///
/// **Audit gap A.2.1.G1, closed 2026-04-26.**  Previously, the SSA
/// summary extractor leaked synthetic external-capture `Param` ops
/// into the summary's parameter-index references, so its FuncKey
/// disambig got synthesised away from the matching FuncSummary
/// FuncKey, and Phase 3's `summaries.get_ssa(caller_key)` lookup
/// missed.  Fix: bound `effective_params` by `formal_param_names.len()`
/// in `extract_ssa_func_summary` so the SSA summary's parameter-index
/// references stay inside the FuncKey arity (see
/// `project_typed_callgraph_audit_gap_ssa_disambig_fix_2026-04-26.md`).
#[test]
fn audit_a21_end_to_end_pipeline_devirt_fires() {
    // FileHandle::close lives on the constructor-injected
    // `FileHandle` container; the second `close` lives on a custom
    // `Cache` container.  Without devirtualisation, today's
    // name-only resolution would have to disambiguate `close()` and
    // would land in `unresolved_ambiguous`.
    let reader = br#"
import java.io.FileInputStream;
class Reader {
    static void read() {
        FileInputStream f = new FileInputStream("/etc/passwd");
        f.close();
    }
}
"#;
    // Two same-name `close()` methods in *separate files*.  The SSA
    // FuncKey identity has to match the FuncSummary FuncKey for Phase
    // 3 to consume `typed_call_receivers`; same-file collisions would
    // mask the gap with `merge_summaries`-side disambig synthesis.
    let file_handle = br#"
class FileHandle {
    void close() {}
}
"#;
    let cache = br#"
class Cache {
    void close() {}
}
"#;

    let gs = pipeline_global_summaries(&[
        File {
            namespace: "Reader.java",
            bytes: reader,
        },
        File {
            namespace: "FileHandle.java",
            bytes: file_handle,
        },
        File {
            namespace: "Cache.java",
            bytes: cache,
        },
    ]);

    // Step 1: SSA extraction recorded the typed receiver.
    let read_sum = find_ssa(&gs, "read", "Reader").expect("Reader::read must have an SSA summary");
    let containers: Vec<&str> = read_sum
        .typed_call_receivers
        .iter()
        .map(|(_, c)| c.as_str())
        .collect();
    assert!(
        containers.contains(&"FileHandle"),
        "FileInputStream-typed receiver must surface as `FileHandle` container; got {:?}",
        read_sum.typed_call_receivers,
    );

    // Step 2: build_call_graph must route the edge to FileHandle::close,
    // not to Cache::close.
    let cg = build_call_graph(&gs, &[]);
    let read_key = FuncKey {
        lang: Lang::Java,
        namespace: "Reader.java".into(),
        container: "Reader".into(),
        name: "read".into(),
        arity: Some(0),
        ..Default::default()
    };
    let read_node = match cg.index.get(&read_key) {
        Some(&n) => n,
        None => {
            // Some Java extractors set kind=Method so the harness
            // FuncKey above might miss.  Fall back to a name-only
            // lookup.
            *cg.index
                .iter()
                .find(|(k, _)| k.name == "read" && k.container == "Reader")
                .map(|(_, n)| n)
                .unwrap_or_else(|| {
                    let keys: Vec<_> = cg.index.keys().collect();
                    panic!("Reader::read node must exist; cg.index keys = {keys:?}");
                })
        }
    };
    use petgraph::visit::EdgeRef;
    let targets: Vec<&FuncKey> = cg
        .graph
        .edges(read_node)
        .map(|e| &cg.graph[e.target()])
        .collect();
    assert!(
        targets
            .iter()
            .any(|k| k.name == "close" && k.container == "FileHandle"),
        "Phase 3 devirt wedge must route f.close() to FileHandle::close; got {targets:?}",
    );
    assert!(
        !targets
            .iter()
            .any(|k| k.name == "close" && k.container == "Cache"),
        "Phase 3 devirt wedge must NOT leak the edge to Cache::close; got {targets:?}",
    );
}

// ─────────────────────────────────────────────────────────────────────
//  A.2.4, SQLite round-trip + rescan-cache parity
// ─────────────────────────────────────────────────────────────────────

/// SQLite round-trip test for `typed_call_receivers`: an SSA summary
/// written to disk and reloaded must carry the same vector.  Pins the
/// `#[serde(default, skip_serializing_if = "Vec::is_empty")]`
/// behaviour: empty vectors compress to a missing field, but non-empty
/// vectors must serialise and deserialise byte-faithfully.
#[test]
fn audit_a24_typed_call_receivers_sqlite_round_trip() {
    use nyx_scanner::database::index;

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("Caller.java");
    std::fs::write(&f, "// caller body").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("audit-proj", &pool).unwrap();

    let hash = index::Indexer::digest_bytes(b"// caller body");
    let typed = vec![
        (0_u32, "FileHandle".to_string()),
        (3_u32, "HttpClient".to_string()),
    ];
    let summary = SsaFuncSummary {
        typed_call_receivers: typed.clone(),
        ..Default::default()
    };
    let row = (
        "doWork".to_string(),
        0_usize,
        "java".to_string(),
        "Caller.java".to_string(),
        "Caller".to_string(),
        None,
        nyx_scanner::symbol::FuncKind::Function,
        summary,
    );

    idx.replace_ssa_summaries_for_file(&f, &hash, &[row])
        .unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 1, "exactly one row should survive round-trip");
    // Output tuple positions: (file_path, name, lang, arity, namespace, container, disambig, kind, summary)
    let (_, name, _, _, _ns, container, _, _, sum) = &loaded[0];
    assert_eq!(name, "doWork");
    assert_eq!(container, "Caller");
    assert_eq!(
        sum.typed_call_receivers, typed,
        "typed_call_receivers must round-trip byte-faithfully"
    );
}

/// SQLite default behaviour: an SSA summary with an empty
/// `typed_call_receivers` vector must round-trip with the field still
/// present and empty.  Backward-compatibility guard: old DB rows with
/// no `typed_call_receivers` field deserialise as empty.
#[test]
fn audit_a24_empty_typed_call_receivers_round_trips_as_empty() {
    use nyx_scanner::database::index;

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("Caller.java");
    std::fs::write(&f, "// caller body").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("audit-proj", &pool).unwrap();

    let hash = index::Indexer::digest_bytes(b"// caller body");
    let summary = SsaFuncSummary::default();
    let row = (
        "noop".to_string(),
        0_usize,
        "java".to_string(),
        "Caller.java".to_string(),
        String::new(),
        None,
        nyx_scanner::symbol::FuncKind::Function,
        summary,
    );

    idx.replace_ssa_summaries_for_file(&f, &hash, &[row])
        .unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    // Output tuple positions: (file_path, name, lang, arity, namespace, container, disambig, kind, summary)
    let (_, _, _, _, _, _, _, _, sum) = &loaded[0];
    assert!(
        sum.typed_call_receivers.is_empty(),
        "default summary's typed_call_receivers must be empty after round-trip"
    );
}

// ─────────────────────────────────────────────────────────────────────
//  A.3 P/N/R matrix
// ─────────────────────────────────────────────────────────────────────

/// P-1: Java `FileInputStream f = new FileInputStream(...); f.close()`
/// surfaces a typed receiver entry with the `FileHandle` container.
/// (Mirrors the unit-level Phase 2 test but goes through the public
/// SSA-extraction API.)
#[test]
fn audit_p1_java_file_input_stream_typed_receiver() {
    let src = br#"
class P {
    void use() {
        java.io.FileInputStream f = new java.io.FileInputStream("/tmp/x");
        f.close();
    }
}
"#;
    let gs = pipeline_global_summaries(&[File {
        namespace: "P.java",
        bytes: src,
    }]);
    let s = find_ssa(&gs, "use", "P").expect("P::use must have summary");
    let containers: Vec<&str> = s
        .typed_call_receivers
        .iter()
        .map(|(_, c)| c.as_str())
        .collect();
    assert!(
        containers.contains(&"FileHandle"),
        "P-1: expected FileHandle container; got {containers:?}"
    );
}

/// P-2: Java `HttpClient.newHttpClient(); c.send(...)`, typed receiver
/// `HttpClient`.  This is the canonical Phase-10 type-inference shape.
#[test]
fn audit_p2_java_http_client_typed_receiver() {
    let src = br#"
import java.net.http.HttpClient;
class P {
    void use() {
        HttpClient c = HttpClient.newHttpClient();
        c.send(null, null);
    }
}
"#;
    let gs = pipeline_global_summaries(&[File {
        namespace: "P.java",
        bytes: src,
    }]);
    let s = find_ssa(&gs, "use", "P").expect("P::use must have summary");
    let containers: Vec<&str> = s
        .typed_call_receivers
        .iter()
        .map(|(_, c)| c.as_str())
        .collect();
    assert!(
        containers.contains(&"HttpClient"),
        "P-2: expected HttpClient container; got {containers:?}"
    );
}

/// P-3: Python `c = sqlite3.connect(...); c.execute(...)`, typed
/// receiver `DatabaseConnection`.
#[test]
fn audit_p3_python_sqlite_connection_typed_receiver() {
    let src = br#"
import sqlite3

def use():
    c = sqlite3.connect("/tmp/x.db")
    c.execute("SELECT 1")
"#;
    let gs = pipeline_global_summaries(&[File {
        namespace: "use.py",
        bytes: src,
    }]);
    let s = find_ssa(&gs, "use", "")
        .or_else(|| find_ssa(&gs, "use", "use.py"))
        .expect("use() must have an SSA summary");
    let containers: Vec<&str> = s
        .typed_call_receivers
        .iter()
        .map(|(_, c)| c.as_str())
        .collect();
    assert!(
        containers.contains(&"DatabaseConnection"),
        "P-3: expected DatabaseConnection container; got {containers:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
//  A.3 negatives
// ─────────────────────────────────────────────────────────────────────

/// N-1: a free-function call (no receiver, `new FileInputStream(...)`
/// with no method-call follow-up) must not surface in
/// `typed_call_receivers`.  Even if the constructor produces a known
/// type, the SSA Call carries `receiver: None` and the devirtualisation
/// path is skipped.
#[test]
fn audit_n1_free_function_call_has_no_typed_entry() {
    let src = br#"
class P {
    void make() {
        new java.io.FileInputStream("/tmp/x");
    }
}
"#;
    let gs = pipeline_global_summaries(&[File {
        namespace: "P.java",
        bytes: src,
    }]);
    let typed = find_ssa(&gs, "make", "P")
        .map(|s| s.typed_call_receivers.clone())
        .unwrap_or_default();
    assert!(
        typed.is_empty(),
        "N-1: free-function constructor must not emit a typed receiver entry; got {typed:?}"
    );
}

/// N-3: Receiver type known but no matching container method ,
/// devirtualisation must NOT silently drop the edge.  Today's
/// name-only resolution still fires and finds the target.  This is
/// the receiver-misclassification fall-through invariant from
/// Phase 3.  We exercise it via the call-graph builder using a
/// hand-constructed `GlobalSummaries` (mirrors
/// `typed_call_receivers_falls_through_on_zero_match` but at the
/// integration-test level).
#[test]
fn audit_n3_zero_match_falls_through_to_today() {
    use nyx_scanner::summary::{CalleeSite, FuncSummary, merge_summaries};

    let make = |name: &str, container: &str, file: &str, arity: usize| FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "rust".into(),
        param_count: arity,
        container: container.into(),
        ..Default::default()
    };

    // Single `process` on `Worker`.  Caller's typed_call_receivers
    // says "Other", there is no such container, so the typed lookup
    // misses and we fall through to today's name-only resolution.
    let worker = make("process", "Worker", "src/worker.rs", 1);
    let caller = FuncSummary {
        name: "drive".into(),
        file_path: "src/main.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        callees: vec![CalleeSite {
            name: "process".into(),
            arity: Some(1),
            receiver: Some("worker".into()),
            ordinal: 0,
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut gs = merge_summaries(vec![worker, caller], None);
    let caller_key = FuncKey {
        lang: Lang::Rust,
        namespace: "src/main.rs".into(),
        name: "drive".into(),
        arity: Some(0),
        ..Default::default()
    };
    gs.insert_ssa(
        caller_key.clone(),
        SsaFuncSummary {
            typed_call_receivers: vec![(0, "Other".to_string())],
            ..Default::default()
        },
    );

    let cg = build_call_graph(&gs, &[]);
    let caller_node = cg.index[&caller_key];
    let edge_count = cg.graph.edges(caller_node).count();
    assert_eq!(
        edge_count, 1,
        "N-3: stale typed receiver must fall through to today's resolution; got {edge_count} edges"
    );
}

/// N-4: A constructor invocation only (no follow-up method call)
/// must leave `typed_call_receivers` empty for that body.  Same
/// rationale as N-1 but exercises the absence of the secondary call.
#[test]
fn audit_n4_constructor_only_body_has_no_typed_entries() {
    // Same-shaped fixture as N-1 but the test is broader: not just
    // the free-function case, but any body where no method call
    // follows the typed allocation.
    let src = br#"
class P {
    void make() {
        java.io.FileInputStream f = new java.io.FileInputStream("/tmp/x");
    }
}
"#;
    let gs = pipeline_global_summaries(&[File {
        namespace: "P.java",
        bytes: src,
    }]);
    let typed = find_ssa(&gs, "make", "P")
        .map(|s| s.typed_call_receivers.clone())
        .unwrap_or_default();
    assert!(
        typed.is_empty(),
        "N-4: constructor-only body must not emit typed receivers; got {typed:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
//  A.3 regressions
// ─────────────────────────────────────────────────────────────────────

/// R-3: Without a typed receiver entry, an ambiguous unqualified call
/// must remain ambiguous (no edge added).  Pin: devirtualisation is
/// strictly additive, it never resolves edges that today's pipeline
/// considers ambiguous unless real type info is present.
#[test]
fn audit_r3_ambiguous_without_typed_receiver_stays_ambiguous() {
    use nyx_scanner::summary::{FuncSummary, merge_summaries};

    let make = |name: &str, file: &str| FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "rust".into(),
        param_count: 0,
        ..Default::default()
    };

    let send_http = make("send", "src/http.rs");
    let send_mail = make("send", "src/mail.rs");
    // Caller in a third file calls bare `send`, genuinely ambiguous.
    let caller = FuncSummary {
        name: "go".into(),
        file_path: "src/main.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        callees: vec!["send".into()],
        ..Default::default()
    };
    let gs = merge_summaries(vec![send_http, send_mail, caller], None);
    let cg = build_call_graph(&gs, &[]);
    let caller_key = FuncKey {
        lang: Lang::Rust,
        namespace: "src/main.rs".into(),
        name: "go".into(),
        arity: Some(0),
        ..Default::default()
    };
    let caller_node = cg.index[&caller_key];
    assert_eq!(
        cg.graph.edges(caller_node).count(),
        0,
        "R-3: bare ambiguous call must stay ambiguous"
    );
    assert_eq!(
        cg.unresolved_ambiguous.len(),
        1,
        "R-3: ambiguity must be recorded for diagnostics"
    );
}

/// R-4: Arity overloads on the same container.  When the typed
/// receiver picks a container that hosts two arity-overloaded
/// methods, the per-call-site `arity` filter must still pick the
/// right one, devirtualisation does not bypass arity narrowing.
#[test]
fn audit_r4_arity_filter_still_applies_after_devirt() {
    use nyx_scanner::summary::{CalleeSite, FuncSummary, merge_summaries};

    let make = |name: &str, container: &str, file: &str, arity: usize| FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "rust".into(),
        param_count: arity,
        container: container.into(),
        ..Default::default()
    };

    let one = make("encode", "Codec", "src/codec.rs", 1);
    let two = make("encode", "Codec", "src/codec.rs", 2);
    let caller = FuncSummary {
        name: "drive".into(),
        file_path: "src/main.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        callees: vec![CalleeSite {
            name: "encode".into(),
            arity: Some(2),
            receiver: Some("c".into()),
            ordinal: 0,
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut gs = merge_summaries(vec![one, two, caller], None);
    let caller_key = FuncKey {
        lang: Lang::Rust,
        namespace: "src/main.rs".into(),
        name: "drive".into(),
        arity: Some(0),
        ..Default::default()
    };
    gs.insert_ssa(
        caller_key.clone(),
        SsaFuncSummary {
            typed_call_receivers: vec![(0, "Codec".to_string())],
            ..Default::default()
        },
    );

    let cg = build_call_graph(&gs, &[]);
    let caller_node = cg.index[&caller_key];
    use petgraph::visit::EdgeRef;
    let targets: Vec<&FuncKey> = cg
        .graph
        .edges(caller_node)
        .map(|e| &cg.graph[e.target()])
        .collect();
    assert_eq!(
        targets.len(),
        1,
        "R-4: arity filter must narrow to the 2-arg overload; got {targets:?}"
    );
    assert_eq!(targets[0].arity, Some(2));
}

/// R-6: Anonymous / closure caller without a stable FuncKey must not
/// panic on the typed_receivers lookup.  Today's resolver treats a
/// missing SSA summary as "no typed receivers" and falls through to
/// name-only resolution; pin this via a synthetic GlobalSummaries
/// where the caller has a `FuncSummary` but no SSA summary.
#[test]
fn audit_r6_anonymous_caller_without_ssa_summary_is_safe() {
    use nyx_scanner::summary::{CalleeSite, FuncSummary, merge_summaries};

    let helper = FuncSummary {
        name: "helper".into(),
        file_path: "src/lib.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        ..Default::default()
    };
    let caller = FuncSummary {
        name: "anon".into(),
        file_path: "src/lib.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        callees: vec![CalleeSite {
            name: "helper".into(),
            arity: Some(0),
            receiver: None,
            ordinal: 0,
            ..Default::default()
        }],
        ..Default::default()
    };

    let gs = merge_summaries(vec![helper, caller], None);
    let cg = build_call_graph(&gs, &[]);
    // Build must finish without panic; the bare call resolves
    // through today's path.
    assert_eq!(
        cg.graph.edge_count(),
        1,
        "R-6: bare caller must still resolve"
    );
}
