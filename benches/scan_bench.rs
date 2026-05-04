use criterion::{Criterion, criterion_group, criterion_main};
use nyx_scanner::utils::Config;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

const FIXTURES: &str = "benches/fixtures";

fn bench_ast_only_scan(c: &mut Criterion) {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures dir");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Ast;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 64;

    c.bench_function("ast_only_scan", |b| {
        b.iter(|| {
            let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
            if let Err(err) = handle.join() {
                panic!("walker panicked: {err:#?}");
            }
            let paths: Vec<_> = rx.into_iter().flatten().collect();
            let mut diags = Vec::new();
            for path in &paths {
                if let Ok(mut d) =
                    nyx_scanner::ast::run_rules_on_file(path, &cfg, None, Some(&fixtures))
                {
                    diags.append(&mut d);
                }
            }
            diags
        });
    });
}

fn bench_full_scan(c: &mut Criterion) {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures dir");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 64;

    c.bench_function("full_scan", |b| {
        b.iter(|| {
            let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
            if let Err(err) = handle.join() {
                panic!("walker panicked: {err:#?}");
            }
            let paths: Vec<_> = rx.into_iter().flatten().collect();

            // Pass 1: extract summaries
            let mut all_sums = Vec::new();
            for path in &paths {
                if let Ok(sums) = nyx_scanner::ast::extract_summaries_from_file(path, &cfg) {
                    all_sums.extend(sums);
                }
            }
            let root_str = fixtures.to_string_lossy();
            let global = nyx_scanner::summary::merge_summaries(all_sums, Some(&root_str));

            // Pass 2: full analysis
            let mut diags = Vec::new();
            for path in &paths {
                if let Ok(mut d) =
                    nyx_scanner::ast::run_rules_on_file(path, &cfg, Some(&global), Some(&fixtures))
                {
                    diags.append(&mut d);
                }
            }
            diags
        });
    });
}

fn bench_full_scan_with_state(c: &mut Criterion) {
    let fixtures = Path::new(FIXTURES).canonicalize().expect("fixtures dir");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 64;

    c.bench_function("full_scan_with_state", |b| {
        b.iter(|| {
            let (rx, handle) = nyx_scanner::walk::spawn_file_walker(&fixtures, &cfg);
            if let Err(err) = handle.join() {
                panic!("walker panicked: {err:#?}");
            }
            let paths: Vec<_> = rx.into_iter().flatten().collect();

            // Pass 1: extract summaries
            let mut all_sums = Vec::new();
            for path in &paths {
                if let Ok(sums) = nyx_scanner::ast::extract_summaries_from_file(path, &cfg) {
                    all_sums.extend(sums);
                }
            }
            let root_str = fixtures.to_string_lossy();
            let global = nyx_scanner::summary::merge_summaries(all_sums, Some(&root_str));

            // Pass 2: full analysis with state
            let mut diags = Vec::new();
            for path in &paths {
                if let Ok(mut d) =
                    nyx_scanner::ast::run_rules_on_file(path, &cfg, Some(&global), Some(&fixtures))
                {
                    diags.append(&mut d);
                }
            }
            diags
        });
    });
}

fn bench_single_file_parse_and_cfg(c: &mut Criterion) {
    let fixture = Path::new(FIXTURES).join("sample.rs");
    let fixture = fixture.canonicalize().expect("sample.rs fixture");
    let cfg = Config::default();

    c.bench_function("single_file_parse_cfg", |b| {
        b.iter(|| {
            nyx_scanner::ast::extract_summaries_from_file(&fixture, &cfg)
                .expect("extract summaries")
        });
    });
}

fn bench_state_analysis_only(c: &mut Criterion) {
    let fixture = Path::new(FIXTURES)
        .join("state_bench.c")
        .canonicalize()
        .expect("state_bench.c fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;

    // Parse and build CFG once (outside benchmark loop)
    let (file_cfg, lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg)
        .expect("build cfg")
        .expect("supported language");
    let source_bytes = std::fs::read(&fixture).expect("read fixture");
    let top = file_cfg.toplevel();

    c.bench_function("state_analysis_only", |b| {
        b.iter(|| {
            nyx_scanner::state::run_state_analysis(
                &top.graph,
                top.entry,
                lang,
                &source_bytes,
                &file_cfg.summaries,
                None,
                true,
                &[],
                &[],
                &std::collections::HashSet::new(),
                None,
                None,
            )
        });
    });
}

fn bench_classify(c: &mut Criterion) {
    c.bench_function("classify_hit", |b| {
        b.iter(|| nyx_scanner::labels::classify("rust", "std::env::var", None));
    });

    c.bench_function("classify_miss", |b| {
        b.iter(|| nyx_scanner::labels::classify("rust", "some_random_function", None));
    });
}

/// Per-file fused analysis throughput on a realistic ~1.5k-line Go module
/// (gin context.go, ~147 fns).  Guards the
/// `ParsedFile::body_const_facts_cache` optimization that collapses the
/// 2-3× per-body re-lowering that previously dominated `analyse_file_fused`
/// (~14% of wall-clock on the gin-scan profile).  Regressions here mean
/// per-body work is being recomputed across passes again.
fn bench_analyse_file_fused_large_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);

    // One-shot diagnostic: count `build_body_const_facts` calls per fused
    // analysis so a regression that removes the per-file cache surfaces here
    // (expected ~148 calls on this fixture; pre-cache was ~444).
    nyx_scanner::cfg_analysis::BUILD_BODY_CONST_FACTS_CALLS
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
        .expect("warmup analyse");
    let calls = nyx_scanner::cfg_analysis::BUILD_BODY_CONST_FACTS_CALLS
        .load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("[diag] build_body_const_facts calls per analyse_file_fused: {calls}");

    c.bench_function("analyse_file_fused_large_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
                .expect("analyse_file_fused")
        });
    });
}

/// Per-file `extract_authorization_model` throughput on the realistic
/// ~1.5k-line Go fixture (gin context.go).  Guards the
/// `extract_authorization_model` orchestrator hoist that pulled the
/// shared `collect_top_level_units` AST walk out of every supporting
/// extractor's `extract()` (one walk per file instead of one per
/// matching extractor).  On Go files both `EchoExtractor` and
/// `GinExtractor` match by default — pre-hoist this bench measured the
/// AST being walked twice; regressions here mean the hoist has been
/// broken or a new Go extractor was added that re-walks the tree.
fn bench_extract_authorization_model_go(c: &mut Criterion) {
    use tree_sitter::Parser;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");

    let mut parser = Parser::new();
    let go_lang: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
    parser.set_language(&go_lang).expect("set go grammar");
    let tree = parser.parse(&bytes, None).expect("parse fixture");

    let cfg = Config::default();
    let rules = nyx_scanner::auth_analysis::config::build_auth_rules(&cfg, "go");

    c.bench_function("extract_authorization_model_go", |b| {
        b.iter(|| {
            nyx_scanner::auth_analysis::extract::extract_authorization_model(
                "go",
                cfg.framework_ctx.as_ref(),
                &tree,
                &bytes,
                &fixture,
                &rules,
            )
        });
    });
}

/// Per-file shared-vs-double `extract_authorization_model` cost on a
/// realistic Go fixture (gin context.go).  Pre-fix
/// `analyse_file_fused` called `extract_authorization_model` twice per
/// file (once for diagnostics via `run_auth_analysis`, once for
/// per-file summary keying via `extract_auth_summaries_by_key`).  This
/// bench records the **shared-model path** only (extract once, derive
/// both summaries + diagnostics) so a regression that re-introduces
/// the double-call surfaces as a ≥1.7× slowdown here.
fn bench_extract_authorization_model_shared_go(c: &mut Criterion) {
    use tree_sitter::Parser;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");

    let mut parser = Parser::new();
    let go_lang: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
    parser.set_language(&go_lang).expect("set go grammar");
    let tree = parser.parse(&bytes, None).expect("parse fixture");

    let cfg = Config::default();
    let rules = nyx_scanner::auth_analysis::config::build_auth_rules(&cfg, "go");

    c.bench_function("extract_authorization_model_shared_go", |b| {
        b.iter(|| {
            // Mirror `analyse_file_fused`: extract once, derive both
            // per-file summaries (cheap iter over units) AND run the
            // full diagnostic pipeline against the same model.
            let model = nyx_scanner::auth_analysis::extract::extract_authorization_model(
                "go",
                cfg.framework_ctx.as_ref(),
                &tree,
                &bytes,
                &fixture,
                &rules,
            );
            let summaries = nyx_scanner::auth_analysis::extract_auth_summaries_from_model(
                &model, "go", &fixture, None,
            );
            let diags = nyx_scanner::auth_analysis::run_auth_analysis_with_model(
                model, &tree, "go", &fixture, &rules, None, None, None,
            );
            (summaries, diags)
        });
    });
}

/// Per-file `collect_top_level_units` cost on a realistic Go fixture
/// (gin context.go, ~147 functions).  Targets the inner per-function
/// AST-walk path: `collect_top_level_units` →
/// `build_function_unit_with_meta` → `collect_unit_state` (recursive
/// per-AST-node walk that emits per-node value-refs).
///
/// Pre-fix (2026-05-04 perfhunt session-0009) `collect_unit_state`
/// called `extract_value_refs(node, bytes)` at every AST node, and that
/// helper recursively walked the node's full subtree.  Combined with
/// the recursion below, every descendant got walked once for each of
/// its ancestors — total work O(N²) per function body.  The fix
/// replaced that call with an O(1)-per-node `append_shallow_value_ref`
/// helper.  A regression that re-introduces the deep walk surfaces
/// here as a ≥2× slowdown.
fn bench_collect_top_level_units_go(c: &mut Criterion) {
    use tree_sitter::Parser;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");

    let mut parser = Parser::new();
    let go_lang: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
    parser.set_language(&go_lang).expect("set go grammar");
    let tree = parser.parse(&bytes, None).expect("parse fixture");

    let cfg = Config::default();
    let rules = nyx_scanner::auth_analysis::config::build_auth_rules(&cfg, "go");

    c.bench_function("collect_top_level_units_go", |b| {
        b.iter(|| {
            let mut model = nyx_scanner::auth_analysis::model::AuthorizationModel::default();
            nyx_scanner::auth_analysis::extract::common::collect_top_level_units(
                tree.root_node(),
                &bytes,
                &rules,
                &mut model,
            );
            model
        });
    });
}

/// SCCP throughput on every SSA body lowered from the gin context.go
/// fixture.  Targets `nyx_scanner::ssa::const_prop::const_propagate`
/// directly, isolating it from the surrounding `optimize_ssa` pass and
/// the full-fused per-file analysis.
///
/// Pre-fix (2026-05-04 perfhunt) `const_propagate` stored its lattice in
/// `HashMap<SsaValue, ConstLattice>` and walked
/// `inst_uses(inst).contains(&val)` for every block re-evaluation in the
/// SSA worklist — both shapes paid `SipHash` cost on every operand, and
/// the `inst_uses` factory allocated a fresh `Vec<SsaValue>` on every
/// call.  Switching the lattice + executable-edge maps to dense
/// `Vec`-indexed storage and the use-check to a zero-allocation
/// predicate cut `const_propagate` self-time roughly in half on the
/// large-Go fixture.  A regression that re-introduces the hash-keyed
/// inner loop will surface here as a ≥1.4× slowdown.
fn bench_const_propagate_large_go(c: &mut Criterion) {
    use nyx_scanner::ssa;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg_obj = Config::default();
    let (file_cfg, _lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg_obj)
        .expect("build cfg")
        .expect("supported language");

    // Lower every body once outside the bench loop so we measure only
    // SCCP cost.  The collected `(SsaBody, Cfg)` pairs are the input to
    // the inner loop.
    let mut bodies: Vec<ssa::ir::SsaBody> = Vec::new();
    for body in &file_cfg.bodies {
        // Use `body.meta.name` as the scope filter so the SSA lowering
        // pulls only this function's nodes; `scope_all=true` is reserved
        // for the synthetic top-level body where `name` is None.
        let scope = body.meta.name.as_deref();
        let scope_all = scope.is_none();
        match ssa::lower_to_ssa(&body.graph, body.entry, scope, scope_all) {
            Ok(ssa_body) => bodies.push(ssa_body),
            Err(_) => continue,
        }
    }
    eprintln!("[diag] const_propagate bench: {} bodies lowered", bodies.len());

    c.bench_function("const_propagate_large_go", |b| {
        b.iter(|| {
            let mut total_values = 0usize;
            for body in &bodies {
                let result = ssa::const_prop::const_propagate(body);
                total_values += result.values.len();
            }
            total_values
        });
    });
}

criterion_group!(
    benches,
    bench_ast_only_scan,
    bench_full_scan,
    bench_full_scan_with_state,
    bench_single_file_parse_and_cfg,
    bench_state_analysis_only,
    bench_classify,
    bench_analyse_file_fused_large_go,
    bench_extract_authorization_model_go,
    bench_extract_authorization_model_shared_go,
    bench_collect_top_level_units_go,
    bench_const_propagate_large_go,
);
criterion_main!(benches);
