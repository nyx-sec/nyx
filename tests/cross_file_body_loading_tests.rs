//! Smoke test: cross-file SSA bodies load into
//! [`GlobalSummaries::bodies`] from the pass-1 fused pipeline.
//!
//! The body-loading path is pure plumbing: the taint engine carries a
//! `cross_file_bodies` field on `SsaTaintTransfer` that the cross-file
//! inline path consumes.  This test guards the *availability*
//! invariant, if pass 1 stops populating the body map, the inline
//! path would silently fall back to summary resolution even when
//! cross-file bodies could have given context-sensitive precision.
//!
//! Fixture shape: `a.py` defines `helper(token)`, `b.py` calls it.  The
//! test runs pass-1 extraction on both files, merges the results into a
//! `GlobalSummaries`, and asserts the callee body is present with the
//! correct `param_count`.

use nyx_scanner::ast::analyse_file_fused;
use nyx_scanner::summary::GlobalSummaries;
use nyx_scanner::symbol::Lang;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::Path;

/// Test-local config mirror of `tests/common/mod.rs::test_config` ,
/// kept inline so this file does not need to pull in the shared module
/// (which `cargo test --test cross_file_body_loading_tests` would
/// require extra wiring for).
fn test_config() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.scanner.enable_state_analysis = true;
    cfg.scanner.enable_auth_analysis = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 64;
    cfg.performance.channel_multiplier = 1;
    cfg
}

/// Replay the pass-1 body-collection logic from `scan_filesystem` on a
/// handful of files and return the resulting `GlobalSummaries`.
///
/// This mirrors the fold-body of `scan_filesystem`'s pass-1 rayon loop ,
/// the production code uses the same `analyse_file_fused` entry point
/// and the same `insert` / `insert_ssa` / `insert_body` trio.  Keeping
/// the test close to that shape catches drift between the fused pipeline
/// and the summary merge.
fn pass1(root: &Path, paths: &[std::path::PathBuf], cfg: &Config) -> GlobalSummaries {
    let root_str = root.to_string_lossy();
    let mut gs = GlobalSummaries::new();
    for path in paths {
        let bytes = std::fs::read(path).expect("fixture read");
        let r = analyse_file_fused(&bytes, path, cfg, None, Some(root))
            .expect("analyse_file_fused should succeed on a well-formed fixture");
        for s in r.summaries {
            let key = s.func_key(Some(&root_str));
            gs.insert(key, s);
        }
        for (key, ssa) in r.ssa_summaries {
            gs.insert_ssa(key, ssa);
        }
        for (key, body) in r.ssa_bodies {
            gs.insert_body(key, body);
        }
    }
    gs
}

#[test]
fn cross_file_body_loading_smoke_python_two_files() {
    // Fresh tmpdir so the per-run scan root is unambiguous.
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // `a.py` defines a helper that takes one parameter, does a trivial
    // string op, and returns.  The body is intentionally small, we only
    // care that *any* eligible body is produced, not that it has
    // interesting taint content.
    let a_py = root.join("a.py");
    std::fs::write(
        &a_py,
        "def helper(token):\n    cleaned = token.strip()\n    return cleaned\n",
    )
    .expect("write a.py");

    // `b.py` calls the helper.  Needed so pass 1 records the call edge
    // and the callee is a *cross-file* target from b.py's perspective.
    let b_py = root.join("b.py");
    std::fs::write(
        &b_py,
        "from a import helper\n\n\
         def route(request):\n    \
             return helper(request.GET['t'])\n",
    )
    .expect("write b.py");

    let cfg = test_config();
    let gs = pass1(root, &[a_py.clone(), b_py.clone()], &cfg);

    // Availability: the accessor must expose a non-empty map so the
    // inline consumer (`SsaTaintTransfer::cross_file_bodies`) has
    // something to consult on a cross-file call.
    assert!(
        gs.bodies_len() >= 1,
        "pass 1 must populate at least one cross-file SSA body for a two-file fixture; \
         bodies_len = {}. If this fires, check that `cross_file_symex_enabled()` is on \
         (default) and that `analyse_file_fused` still returns `ssa_bodies`.",
        gs.bodies_len()
    );
    // Find the helper entry.  Python stores the enclosing file path as
    // the namespace; we just match on `(lang, name)` to stay robust to
    // path-normalisation tweaks.
    let helper_entry = gs
        .bodies()
        .find(|(k, _)| k.lang == Lang::Python && k.name == "helper")
        .unwrap_or_else(|| {
            panic!(
                "no body entry for Python `helper`; keys = {:?}",
                gs.bodies()
                    .map(|(k, _)| format!("{}::{} ({})", k.namespace, k.name, k.lang.as_str()))
                    .collect::<Vec<_>>()
            )
        });
    let (_, body) = helper_entry;

    assert_eq!(
        body.param_count, 1,
        "helper(token) has a single parameter; body.param_count = {}",
        body.param_count
    );

    // Quick sanity on the SSA shape, an eligible body must have at
    // least one block.  Zero blocks would mean we stored an empty stub,
    // which would let the inline path silently do nothing on every
    // inline attempt.
    assert!(
        !body.ssa.blocks.is_empty(),
        "loaded body must carry a non-empty SSA graph"
    );
}

#[test]
fn cross_file_body_loading_empty_without_callees() {
    // A single file with no inter-procedural flow is still expected to
    // produce a body for its one function, that's what body loading
    // enables.  The *empty* case this test guards is "bodies_by_key
    // returns None when no bodies are loaded," which keeps the
    // threaded-through `Option` explicit for inline consumers.
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Passing zero paths to `pass1` is what flips `bodies_len` to zero.
    let cfg = test_config();
    let gs = pass1(root, &[], &cfg);

    assert_eq!(gs.bodies_len(), 0);
    assert!(
        gs.bodies().next().is_none(),
        "no bodies may be listed when none are loaded"
    );
}
