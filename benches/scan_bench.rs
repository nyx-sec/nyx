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
);
criterion_main!(benches);
