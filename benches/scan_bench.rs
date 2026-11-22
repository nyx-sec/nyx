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

/// Sweep `classify_all` over a realistic per-node Go corpus (a mix of a few
/// sink/source hits and mostly ordinary non-matching callee/identifier texts —
/// the true distribution the CFG-build + taint passes classify, where the
/// overwhelming majority of nodes match nothing).
///
/// Isolates the per-node label-matcher loop that the last-byte `LabelIndex`
/// dispatch replaced: the old path ran `match_suffix_cs` over **every** Go
/// matcher (~150) for every one of these texts; the index visits only the
/// handful sharing the text's last byte. A/B a single binary with
/// `NYX_DISABLE_LABEL_INDEX=1` (forces the pre-index linear scan). A regression
/// here means the dispatch index stopped pruning.
fn bench_classify_all_sweep_go(c: &mut Criterion) {
    // ~60 texts: a handful of real Go sinks/sources + realistic misses
    // (ordinary method names, chained calls, locals) in registry-diverse
    // last bytes.
    let corpus: &[&str] = &[
        // hits (various last bytes)
        "os.Getenv",
        "exec.Command",
        "exec.CommandContext",
        "db.Query",
        "db.QueryRow",
        "db.Exec",
        "fmt.Fprintf",
        "template.HTML",
        "os.ReadFile",
        "ioutil.ReadFile",
        "r.URL.Query().Get",
        "http.Get",
        // misses — ordinary code the classifier still scans every node of
        "handleRequest",
        "s.doWork",
        "ctx.Done",
        "w.WriteHeader",
        "json.Marshal",
        "strings.TrimSpace",
        "append",
        "make",
        "len",
        "buf.String",
        "logger.Info",
        "logger.Debugf",
        "user.Name",
        "cfg.Load",
        "srv.Shutdown",
        "wg.Wait",
        "mu.Lock",
        "mu.Unlock",
        "time.Now",
        "rand.Intn",
        "errors.New",
        "fmt.Errorf",
        "b.Bytes",
        "req.Context",
        "resp.Body.Close",
        "router.Group",
        "c.JSON",
        "c.Param",
        "svc.repo.FindByID",
        "helper.normalize",
        "x",
        "yy",
        "totalCount",
        "isValid",
        "parsePayload",
        "computeHash",
        "sched.next",
        "conn.readLoop",
        "p.marshalTo",
        "node.left",
        "tree.insert",
        "cache.evict",
        "metrics.observe",
        "span.End",
    ];
    c.bench_function("classify_all_sweep_go", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for &t in corpus {
                n += nyx_scanner::labels::classify_all("go", std::hint::black_box(t), None).len();
            }
            std::hint::black_box(n)
        });
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
///
/// Also guards the 2026-07-15 (perfhunt session-0051) NextAuth per-unit
/// walk gate: `body_returns_nextauth_options` scanned every unit body for
/// JS/TS `object` literal nodes even on Go, where it always returns
/// `false`.  The gate (`AuthAnalysisRules::is_object_literal_lang`) skips
/// that fruitless whole-body walk on the ~147 Go functions in this
/// fixture; a regression that drops the gate re-introduces the per-unit
/// walk here.  `NYX_DISABLE_AUTH_WALK_GATE=1` reverts to the old path.
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
                None,
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
                None,
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

/// Per-file gitea `extract_route_handler_auth_edges` cost on the realistic
/// ~1.5k-line Go fixture (gin context.go — no `web.Router` closure groups).
///
/// The gitea extractor harvests cross-file route→handler authorization edges
/// by walking the whole tree of every Go file (`harvest_edges`).  On a file
/// with no `<r>.Group(...)` / `<r>.PathGroup(...)` closure group the walk emits
/// nothing, yet pre-2026-07-15 (perfhunt session-0051) it still descended the
/// entire tree per Go file.  The fix short-circuits on a cheap `Group`
/// byte-substring pre-filter (a gitea edge is emitted only from inside a
/// matched `Group` / `PathGroup` call, both of which contain that token), so a
/// non-gitea Go file skips the walk.  This bench measures that skip; a
/// regression that drops the pre-filter surfaces here as a ≥10× slowdown.
fn bench_gitea_route_auth_edges_go(c: &mut Criterion) {
    use tree_sitter::Parser;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");

    let mut parser = Parser::new();
    let go_lang: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
    parser.set_language(&go_lang).expect("set go grammar");
    let tree = parser.parse(&bytes, None).expect("parse fixture");

    c.bench_function("gitea_route_auth_edges_go", |b| {
        b.iter(|| {
            nyx_scanner::auth_analysis::extract::gitea::extract_route_handler_auth_edges(
                &tree,
                &bytes,
                nyx_scanner::symbol::Lang::Go,
            )
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
///
/// Also guards the 2026-07-14 (perfhunt session-0030) `collect_call`
/// redundancy elimination: `collect_call` was profiled as the single
/// dominant caller of alloc / memmove / from_utf8 on mm/channels/app.
/// The fix removed the duplicate per-argument `extract_value_refs` walk
/// (the old code ran it twice: once for `subjects`, once for
/// `args_value_refs`), made `subjects` lazy (built only for auth checks /
/// sensitive operations), borrowed the whole-call text as `&str` instead
/// of allocating a `String` on every call, and moved `string_args` into
/// the `CallSite` instead of cloning it when no auth check needs it.
/// Non-overlapping criterion CIs recorded the elimination (before
/// [4.3815, 4.4010] ms → after [4.3227, 4.3462] ms, -1.3%); the
/// isolated win is Amdahl-diluted at whole-scan.  A regression that
/// re-introduces the duplicate `extract_value_refs` or the eager
/// `subjects` / `node_text` allocations surfaces here.
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
///
/// 2026-07-15 perfhunt session-0048 additionally removed the residual
/// per-iteration clones from the SCCP worklist: the spurious
/// `use_sites[val_idx].clone()` (a `SmallVec` heap clone per popped value),
/// the `let old = lookup(..)` lattice clone before every change-check (now
/// a borrowing `changed_from`), and the per-phi-operand `lookup` clone (now
/// a borrowing `lookup_ref` fed straight into `meet`).  Bit-identical;
/// criterion here 186.5 → 172.8 µs (−6%).  Re-introducing any of those
/// clones surfaces as a regression on this fixture.
///
/// 2026-07-15 perfhunt session-0054 landed the last structural residual: the
/// public `ConstPropResult.values` (and `OptimizeResult.const_values`) is now
/// a dense `ConstValues(Vec<ConstLattice>)` newtype into which `const_propagate`
/// **moves** its internal `Vec` — eliminating the old `O(num_values)` per-body
/// `HashMap<SsaValue, ConstLattice>` build (one SipHash insert per value,
/// discarded next scan) and turning every downstream `.get(&v)` into a
/// bounds-checked array index.  Single-binary A/B: run once normally and once
/// with `NYX_CONST_VALUES_LEGACY_BUILD=1` (which reproduces the old per-value
/// hashed build).  A regression that re-materialises the result HashMap
/// surfaces here proportional to value count.
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
    eprintln!(
        "[diag] const_propagate bench: {} bodies lowered",
        bodies.len()
    );

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

/// SCCP on a function whose join block has thousands of predecessors.
///
/// The fixture is a C `switch` with one `case N: x = N; break;` arm per
/// constant, so the exit block's phi for `x` has one operand per arm and the
/// join gains one incoming edge per arm.  Evaluating that phi from scratch for
/// every new edge, with a linear executable-predecessor scan per operand, is
/// cubic in the arm count (about 78 s for 3000 arms in a full scan before the
/// fix); with edges queued once and operands absorbed one at a time it is
/// linear.  A regression shows up here as a jump from microseconds to seconds.
fn bench_const_propagate_wide_switch(c: &mut Criterion) {
    use nyx_scanner::ssa;

    let arms = 2000;
    let mut src = String::from("int f(int sel) {\n    int x = 0;\n    switch (sel) {\n");
    for i in 0..arms {
        src.push_str(&format!("    case {i}: x = {i}; break;\n"));
    }
    src.push_str("    }\n    return x;\n}\n");
    let dir = std::env::temp_dir().join("nyx_bench_wide_switch");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let fixture = dir.join("wide_switch.c");
    std::fs::write(&fixture, src).expect("write fixture");

    let cfg_obj = Config::default();
    let (file_cfg, _lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg_obj)
        .expect("build cfg")
        .expect("supported language");
    let bodies: Vec<ssa::ir::SsaBody> = file_cfg
        .bodies
        .iter()
        .filter_map(|body| {
            let scope = body.meta.name.as_deref();
            ssa::lower_to_ssa(&body.graph, body.entry, scope, scope.is_none()).ok()
        })
        .collect();

    c.bench_function("const_propagate_wide_switch", |b| {
        b.iter(|| {
            let mut total_values = 0usize;
            for body in &bodies {
                total_values += ssa::const_prop::const_propagate(body).values.len();
            }
            total_values
        });
    });
}

/// `GlobalSummaries::lookup_same_lang` cost on a populated index.  The
/// inner loop hashes `(Lang, String)` once per call, then `FuncKey` once
/// per candidate via `by_key.get(k)`.  Pre-fix the four secondary
/// indices used `std::collections::HashMap` (SipHash).  Post-fix
/// (2026-05-04 perfhunt session-0015) they use `rustc_hash::FxHashMap`,
/// trading DoS hardening (irrelevant for in-process program-keyed
/// indices) for ~5x faster hashing on the 30+ byte 3-string `FuncKey`
/// hash workload.  A regression that re-introduces SipHash would
/// surface here as a ≥3x slowdown.
fn bench_global_summaries_lookup_same_lang_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg = Config::default();

    let summaries =
        nyx_scanner::ast::extract_summaries_from_file(&fixture, &cfg).expect("extract summaries");
    let names: Vec<String> = summaries.iter().map(|s| s.name.clone()).collect();
    let global = nyx_scanner::summary::merge_summaries(summaries, None);
    let lang = nyx_scanner::symbol::Lang::Go;

    eprintln!("[diag] lookup_same_lang bench: {} names", names.len());

    c.bench_function("global_summaries_lookup_same_lang_go", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for name in &names {
                total += global.lookup_same_lang(lang, name).len();
            }
            total
        });
    });
}

/// Callee-resolution throughput on a high-function-count, high-call-density
/// Go file (`callee_resolve_stress.go`: ~400 functions, ~1680 intra-file
/// call sites).  Guards the per-file [`FuncNameIndex`] that replaced the
/// linear `local_summaries.keys()` scans inside `resolve_callee_full`
/// (`caller_container_for`, `resolve_local_func_key_query`,
/// `resolve_local_func_key`, and the ambiguity probe).  Before the index
/// each of the ~1680 call-site resolutions scanned all ~400 functions
/// (`O(C·F)` ≈ `O(F²)` per file, run once per taint pass — summary
/// extraction, the main analysis, child-sink augmentation).  A regression
/// that reintroduces the linear scan surfaces here as a large slowdown
/// that grows quadratically with the fixture's function count.
///
/// Also guards the borrow-vs-clone candidate API (session-0036): the four
/// resolvers above consult the index via `with_indexed_local_candidates`,
/// which hands them borrowed `&FuncKey`s instead of the former
/// `indexed_local_candidates`, which deep-cloned every same-name candidate
/// (three `String` allocations per `FuncKey`) on each resolution only to be
/// filtered and discarded. The sole surviving clone is the single winning
/// key each resolver returns. Reintroducing the per-resolution candidate-list
/// clone regresses here (measured -2.2% cooled on this fixture).
///
/// Also guards the per-call path-confinement gate hoist (session-0039): this
/// call-dense fixture has no confiner summary (Go produces none), so before the
/// hoist the three per-call confinement passes — `apply_call_post_confinement`,
/// `apply_path_validator_confinement` (a `to_snake_lower` alloc + ~20 substring
/// `contains` scans of the callee name), `apply_call_return_confinement` — ran
/// unconditionally on every call in both the dataflow and event replays, ~5
/// passes per body. `compute_confinement_gates` now computes the "any confiner?"
/// existence check once per body and skips all three when the gate is closed.
/// A/B from one binary via `NYX_DISABLE_CONFINEMENT_GATE=1` (forces the gates
/// open = pre-hoist behaviour); reintroducing the unconditional passes regresses
/// here proportional to the call density.
fn bench_taint_callee_resolve_stress_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/callee_resolve_stress.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);

    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
        .expect("warmup analyse");

    c.bench_function("taint_callee_resolve_stress_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
                .expect("analyse_file_fused")
        });
    });
}

/// Stresses the SSA taint worklist's state-clone path
/// (`run_ssa_taint_internal` in `src/taint/ssa_transfer/mod.rs`).  The
/// fixture is branch- and constraint-dense: every function threads a
/// tainted source through a long chain of `if`/`else` guards plus a loop,
/// so `SsaTaintState::path_env` is non-empty across many basic blocks.  The
/// worklist clones the full state on every block pop, exit store, and
/// per-successor push; before the `Arc`-COW change each clone deep-copied
/// the `PathEnv` (`UnionFind` + five `SmallVec`s — ≈3.9% of static CPU on
/// Go corpora).  After the change those clones are refcount bumps and the
/// `PathEnv` is copied at most once per block (only when it actually
/// mutates).  Measured −12% on this bench when the COW landed
/// (2026-06-12); a regression that drops the `Arc` (or makes `make_mut`
/// fire per instruction) surfaces here as a slowdown proportional to
/// block × constraint density.  `Arc` (not `Rc`) keeps `SsaTaintState`
/// `Send` for the rayon-parallel file scan.
///
/// Also guards the `block_exit_states` clone elision (2026-07-14): the
/// worklist used to `SsaTaintState::clone()` the exit state into
/// `block_exit_states[bid]` on *every* block pop, but the dominant callers
/// (`run_ssa_taint_full`: summary extraction + main analysis + sink
/// augmentation) discard that vector.  It is now built only when the caller
/// asks (`track_exit_states`), and even then the state is *moved* in after
/// its last borrow instead of cloned.  This block-dense fixture maximises
/// pops, so re-introducing the per-pop exit clone surfaces here (measured
/// −1.8% end-to-end when the elision landed; the worklist itself is ~1/3 of
/// `analyse_file_fused`, so the isolated worklist gain is proportionally
/// larger).
fn bench_taint_branch_stress_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/taint_branch_stress.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);

    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
        .expect("warmup analyse");

    c.bench_function("taint_branch_stress_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
                .expect("analyse_file_fused")
        });
    });
}

/// Branch conditions INSIDE nested loops, so the taint worklist re-visits
/// loop-body blocks until fixpoint and (before the memo) re-classified the
/// same condition text on every re-visit.  Isolates the per-condition
/// classification cache: each branch's `classify_condition_with_target` /
/// `has_semantic_negation` / PathFact-classifier `str::find`/`str::contains`
/// scans run once per distinct condition text via the persistent per-thread
/// `COND_CLASS_CACHE`, rather than once per re-visit / pass.  `analyse_file_fused`
/// runs the body's worklist ~5× (summary extraction + main + sink
/// augmentation), and criterion keeps the thread-local warm across `b.iter()`
/// iterations, so this bench captures the cross-pass / cross-iteration reuse
/// the persistent cache adds over the worklist-local memo
/// (session-0018: −2.5% vs worklist-local, −12.5% vs `NYX_DISABLE_COND_MEMO=1`).
/// Reverting the cache to per-`run_ssa_taint_internal` (or recompute-per-visit)
/// surfaces here proportional to the loop re-visit count × pass count.
fn bench_taint_cond_revisit_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/taint_cond_revisit.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.enable_state_analysis = true;
    cfg.performance.worker_threads = Some(1);

    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
        .expect("warmup analyse");

    c.bench_function("taint_cond_revisit_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, &fixture, &cfg, None, None)
                .expect("analyse_file_fused")
        });
    });
}

/// CFG-construction throughput on the large gin Go module (~1.5k lines,
/// selector-expression-dense).  Targets `build_cfg_for_file`, whose hot
/// inner path runs `push_node` → `first_member_label` → `member_expr_text`
/// on every `CallWrapper`/`Assignment` node.  Pre-fix `member_expr_text`
/// built its dot-joined member path bottom-up via a `format!("{o}.{p}")`
/// chain, allocating one intermediate `String` per nesting level (and the
/// `first_member_label` classify path threw every one of those Strings away
/// after a single `classify(&str)` call).  The fix rewrote the builder to
/// append directly into a single reused buffer (`member_expr_text_into`),
/// collapsing the O(depth) intermediate allocations to one final allocation
/// (zero on the `first_member_label` classify path, which uses a thread-local
/// scratch buffer).  This bench isolates that allocation churn — the biggest
/// self-time bucket on the mm/channels/app static profile — from the taint /
/// SSA passes.  A regression that reintroduces the per-level `format!` chain
/// surfaces here proportional to member-expression nesting depth.
fn bench_cfg_build_large_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg = Config::default();

    c.bench_function("cfg_build_large_go", |b| {
        b.iter(|| {
            nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg)
                .expect("build cfg")
                .expect("supported language")
        });
    });
}

/// AST pattern-query pass throughput on the large gin Go module.
///
/// Targets `ParsedSource::run_ast_queries` (via the `bench_run_ast_queries`
/// hook), isolating it from the rest of the per-file pipeline. Pre-fix the
/// pass issued one `QueryCursor::matches` — i.e. one full tree walk — per rule
/// (Go: 8 rules, JS/TS: 23), so traversal cost was `O(rules × nodes)`. The
/// combined multi-pattern query walks the AST once and tests every rule in a
/// single matcher pass (`O(nodes)`); on the mm/channels/app profile
/// `run_ast_queries` was the single biggest active nyx self-time bucket
/// (tree-sitter-cursor work). A/B the two paths on one binary via
/// `NYX_DISABLE_QUERY_COMBINE=1 … --save-baseline legacy` then `… --baseline
/// legacy`. A regression that reverts to per-rule walks surfaces here
/// proportional to the rule count.
fn bench_ast_queries_large_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let cfg = Config::default();

    // Warm the per-language combined-query cache before timing.
    let _ = nyx_scanner::ast::bench_run_ast_queries(&bytes, &fixture, &cfg);

    c.bench_function("ast_queries_large_go", |b| {
        b.iter(|| nyx_scanner::ast::bench_run_ast_queries(&bytes, &fixture, &cfg).len());
    });
}

/// Node-text extraction throughput on the large-Go fixture: decode every node's
/// text via `slice_str` (the `text_of` primitive).  Pre-2026-07-14 every call
/// re-ran `core::str::from_utf8` (`run_utf8_validation`, `O(range_len)`) over
/// the node's byte range, ~1.6% of active CPU on mattermost.  The pre-validated
/// source cache ([`ValidSourceGuard`]) validates the whole file once at parse
/// time and turns each `slice_str` into an `O(1)` `str::get` boundary slice of
/// the already-validated bytes.  Single-binary A/B: run once normally (fast
/// path) and once with `NYX_DISABLE_SRC_STR_CACHE=1` (checked baseline).  A
/// regression that drops the cache surfaces here proportional to node count.
fn bench_node_text_walk_large_go(c: &mut Criterion) {
    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let bytes = std::fs::read(&fixture).expect("read fixture");

    c.bench_function("node_text_walk_large_go", |b| {
        b.iter(|| {
            std::hint::black_box(nyx_scanner::ast::bench_node_text_walk(
                std::hint::black_box(&bytes),
                &fixture,
            ))
        });
    });
}

/// `lower_to_ssa` cost on the large-Go fixture.  This is the CFG→SSA
/// lowering path: `form_blocks` (basic-block formation over the reachable
/// node set) plus `rename_variables`/`process_block` (Cytron dominator-tree
/// rename, which pushes/pops per-variable SSA stacks).  Pre-2026-07-13 the
/// node-keyed maps in `form_blocks` (`successors`, `in_degree`,
/// `has_branching_in`, `is_leader`, `block_of_node`, and the BFS visited
/// sets) and the string-keyed `var_stacks` used `std::collections::HashMap`
/// (SipHash), which profiling showed as ~26% of all SipHash self-time on
/// mattermost (`process_block` + `lower_to_ssa_inner`).  Post-fix they use
/// `rustc_hash::FxHashMap`/`FxHashSet`: keys are dense `NodeIndex` integers
/// or short variable-name strings, none are iterated in an output-observable
/// order, so the cheaper deterministic hasher is bit-identical.  A
/// regression that re-introduces SipHash on this path surfaces here.
///
/// 2026-07-14 (perfhunt session-0015) extended the conversion to the four
/// maps `lower_to_ssa` *returns* inside `SsaBody` — `cfg_node_map`
/// (`NodeIndex`→`SsaValue`), `field_writes`, `synthetic_externals`,
/// `slot_scoped_assigns` — which had stayed `std::collections::HashMap`/
/// `HashSet` because they cross the return boundary into the taint / guards /
/// symex consumers and the `CalleeSsaBody` DB blob.  All consumer accesses are
/// point lookups (audited: the only iteration is the order-insensitive
/// `ssa::invariants` validation), and `FxHashMap` serialises to the identical
/// msgpack map form, so the swap is bit-identical and blob-compatible.  This
/// bench builds `cfg_node_map` on every lowered body, so a regression that
/// reverts those fields to SipHash surfaces here proportional to node count.
fn bench_ssa_lower_large_go(c: &mut Criterion) {
    use nyx_scanner::ssa;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg_obj = Config::default();
    let (file_cfg, _lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg_obj)
        .expect("build cfg")
        .expect("supported language");

    // Snapshot the (graph, entry, scope) inputs once; the bench loop re-runs
    // `lower_to_ssa` on each so we measure only lowering cost, not CFG build.
    let inputs: Vec<(usize, bool)> = file_cfg
        .bodies
        .iter()
        .enumerate()
        .map(|(i, body)| (i, body.meta.name.is_none()))
        .collect();

    c.bench_function("ssa_lower_large_go", |b| {
        b.iter(|| {
            let mut total_blocks = 0usize;
            for &(i, scope_all) in &inputs {
                let body = &file_cfg.bodies[i];
                let scope = body.meta.name.as_deref();
                if let Ok(ssa_body) = ssa::lower_to_ssa(&body.graph, body.entry, scope, scope_all) {
                    total_blocks += ssa_body.blocks.len();
                }
            }
            total_blocks
        });
    });
}

/// Isolates the `cfg_node_map` **point-lookup** path — the map's hottest access
/// pattern (18 `.get()` sites across taint / guards / symex / const-prop resolve
/// a sink or source CFG node to its primary `SsaValue`).
///
/// Pre-2026-07-14 this was a `std::collections::HashMap<NodeIndex, SsaValue>`
/// (SipHash), then an `FxHashMap` (session-0015).  2026-07-14 (session-0018)
/// replaced it with a positional `CfgNodeMap` (`Vec<Option<SsaValue>>` indexed by
/// `NodeIndex::index()`) — the option-(b) deep fix in `PERF_DEFERRED.md`.  A
/// lookup is now a bounds-checked `Vec` index with **zero hashing** instead of an
/// `FxHash` of the `NodeIndex` plus a bucket probe.  A regression that re-hashes
/// the key surfaces here proportional to the number of value-defining nodes.
///
/// Sourced from `value_defs` (not `cfg_node_map.iter()`) so the bench compiles
/// identically against the old `FxHashMap` and the new `CfgNodeMap`, enabling a
/// clean `--save-baseline` before/after on the same bench.
fn bench_cfg_node_map_lookup(c: &mut Criterion) {
    use nyx_scanner::ssa;

    let fixture = Path::new("benches/perf_fixtures/large_go_module.go")
        .canonicalize()
        .expect("perf fixture");
    let cfg_obj = Config::default();
    let (file_cfg, _lang) = nyx_scanner::ast::build_cfg_for_file(&fixture, &cfg_obj)
        .expect("build cfg")
        .expect("supported language");

    // Lower every body once (outside the measured loop); keep each lowered body
    // paired with the value-defining CFG node indices — the realistic lookup
    // keys.
    let probes: Vec<_> = file_cfg
        .bodies
        .iter()
        .filter_map(|body| {
            let scope = body.meta.name.as_deref();
            let scope_all = body.meta.name.is_none();
            ssa::lower_to_ssa(&body.graph, body.entry, scope, scope_all)
                .ok()
                .and_then(|ssa_body| {
                    let nodes: Vec<_> = ssa_body.value_defs.iter().map(|vd| vd.cfg_node).collect();
                    if nodes.is_empty() {
                        None
                    } else {
                        Some((ssa_body, nodes))
                    }
                })
        })
        .collect();

    c.bench_function("cfg_node_map_lookup", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for (ssa_body, nodes) in &probes {
                for n in nodes {
                    if let Some(v) = ssa_body.cfg_node_map.get(n) {
                        acc = acc.wrapping_add(v.0 as u64);
                    }
                }
            }
            acc
        });
    });
}

/// Isolates `FuncKey` hashing on the pessimal map: a `std::collections::HashMap`
/// (SipHash `RandomState`), the exact type used by the interprocedural indices
/// `ssa_by_key` / `bodies_by_key` / `auth_by_key` in `GlobalSummaries`.
///
/// Pre-fix, `FuncKey` derived `Hash`, so every lookup walked all bytes of the
/// three `String` identity fields (project-relative namespace path ~40-50 B,
/// container, name) through SipHash's per-byte mixing.  Profiling attributed
/// 44.7% of all SipHash self-time (~3.8% active CPU) on mattermost's
/// `server/channels/app` to `FuncKey::hash` — the single largest hashed entity
/// in the engine (PERF_DEFERRED.md, 2026-07-13).
///
/// Post-fix (2026-07-14 perfhunt session-0012), `FuncKey` caches a `u64`
/// FxHash of its identity computed once at construction; the manual `Hash`
/// impl writes that single precomputed `u64`, so a lookup mixes 8 bytes
/// instead of the ~76 B of identity string this fixture uses.  The change is
/// asymptotic in the identity string length: `O(len)` → `O(1)` per hash.  A
/// regression that reverts to hashing the string fields surfaces here
/// proportional to the namespace + name lengths.
fn bench_funckey_hash_lookup(c: &mut Criterion) {
    use nyx_scanner::symbol::{FuncKey, Lang};
    use std::collections::HashMap;

    // Realistic identity shapes: deep namespace paths + service-method names,
    // mirroring how cross-file callee keys look on a large Go/Java repo.
    let keys: Vec<FuncKey> = (0..500)
        .map(|i| {
            FuncKey::new_function(
                Lang::Go,
                format!(
                    "server/channels/app/module_group_{}/handler_{:04}.go",
                    i % 16,
                    i
                ),
                format!("Process{:04}RequestHandler", i),
                Some((i % 5) + 1),
            )
        })
        .collect();
    let map: HashMap<FuncKey, usize> = keys
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, k)| (k, i))
        .collect();

    c.bench_function("funckey_hash_lookup", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for k in &keys {
                if let Some(v) = map.get(k) {
                    hits += *v & 1;
                }
            }
            hits
        });
    });
}

/// Isolates the auth-name matcher `matches_name` on a realistic
/// O(call-names × patterns) matrix — mirroring the auth-extraction pass,
/// which checks every call node's callee against dozens of guard/auth
/// patterns per node.  Guards the zero-alloc `canon_has_prefix` stream that
/// replaced two throwaway `canonical_name` `String` allocations per
/// comparison (the `matches_name`/`canonical_name` subtree was ~8.8% of
/// active CPU on mm/channels/app before the fix).  Single-binary A-B via
/// `NYX_DISABLE_CANON_STREAM=1` (forces the legacy allocating path).
fn bench_auth_matches_name(c: &mut Criterion) {
    use nyx_scanner::auth_analysis::config::matches_name;

    // Callee names as they appear on a real Go/JS scan: dotted receiver
    // chains, mixed case, and a majority that miss every auth pattern
    // (the common case that still pays the allocation in the old path).
    let names: Vec<&str> = vec![
        "s.store.User().Get",
        "a.srv.Platform().GetUser",
        "c.App.SessionHasPermissionTo",
        "web.Handler.ServeHTTP",
        "model.User.IsValid",
        "sql.DB.QueryContext",
        "require_trip_member",
        "checkOwnership",
        "isAdmin",
        "hasWorkspaceMembership",
        "before_action",
        "PreAuthorize",
        "user.repo.save",
        "Model.objects.filter",
        "fmt.Sprintf",
        "strings.HasPrefix",
        "json.Marshal",
        "ctx.Done",
        "r.URL.Query().Get",
        "db.Tx(opts).Query",
        "utils.GenerateId",
        "logger.Debug",
        "make",
        "append",
        "getRandomBytes",
    ];
    // The union of literal auth/guard patterns matched per call node.
    let patterns: Vec<&str> = vec![
        "PreAuthorize",
        "Secured",
        "RolesAllowed",
        "hasRole",
        "hasAuthority",
        "requireRole",
        "permission_required",
        "PermissionRequiredMixin",
        "user_passes_test",
        "isAuthenticated",
        "authenticated",
        "isAdmin",
        "checkMembership",
        "hasWorkspaceMembership",
        "isMember",
        "requireMembership",
        "check_membership",
        "checkOwnership",
        "isOwner",
        "requireOwnership",
        "check_ownership",
        "is_owner",
        "owner?",
        "before_action",
        "prepend_before_action",
        "skip_before_action",
        "method_decorator",
        "require_http_methods",
        "get",
        "filter",
        "first",
        "one",
    ];

    c.bench_function("auth_matches_name", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for n in &names {
                for p in &patterns {
                    if matches_name(std::hint::black_box(n), std::hint::black_box(p)) {
                        hits += 1;
                    }
                }
            }
            hits
        });
    });
}

/// Write `count` generated source files into a fresh temp dir and return the
/// dir plus the file list.  Shared by the surface-map benches.
fn write_corpus(
    tag: &str,
    count: usize,
    ext: &str,
    gen_file: impl Fn(usize) -> String,
) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    let dir = std::env::temp_dir().join(format!("nyx_bench_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create corpus dir");
    let mut files = Vec::with_capacity(count);
    for i in 0..count {
        let path = dir.join(format!("f{i:04}.{ext}"));
        std::fs::write(&path, gen_file(i)).expect("write corpus file");
        files.push(path);
    }
    (dir, files)
}

fn surface_inputs_run(files: &[std::path::PathBuf], root: &Path, cfg: &Config) -> usize {
    use nyx_scanner::summary::GlobalSummaries;
    let gs = GlobalSummaries::new();
    let cg = nyx_scanner::callgraph::build_call_graph(&gs, &[]);
    let map = nyx_scanner::surface::build::build_surface_map(
        &nyx_scanner::surface::build::SurfaceBuildInputs {
            files,
            scan_root: Some(root),
            global_summaries: &gs,
            call_graph: &cg,
            config: cfg,
        },
    );
    map.nodes.len()
}

/// `build_surface_map` over a multi-file JS + Java corpus.  The per-file
/// probes run on the rayon pool; a regression to the serial re-read /
/// re-parse loop shows up here as a multiple of the core count.
fn bench_surface_build_corpus(c: &mut Criterion) {
    let (js_dir, mut files) = write_corpus("surf_js", 240, "js", |i| {
        let mut src = String::from("const express = require('express');\nconst app = express();\n");
        for r in 0..24 {
            src.push_str(&format!(
                "app.get('/r{i}/{r}', requireAuth, (req, res) => {{ res.send(req.query.q{r}); }});\n"
            ));
        }
        src
    });
    let (java_dir, java_files) = write_corpus("surf_java", 120, "java", |i| {
        let mut src = format!(
            "import org.springframework.web.bind.annotation.*;\n@RestController\n@RequestMapping(\"/c{i}\")\npublic class C{i} {{\n"
        );
        for r in 0..16 {
            src.push_str(&format!(
                "  @GetMapping(\"/m{r}\")\n  public String m{r}(@RequestParam String q) {{ return q; }}\n"
            ));
        }
        src.push_str("}\n");
        src
    });
    files.extend(java_files);
    let cfg = Config::default();
    c.bench_function("surface_build_corpus", |b| {
        b.iter(|| surface_inputs_run(&files, &js_dir, &cfg));
    });
    let _ = std::fs::remove_dir_all(&js_dir);
    let _ = std::fs::remove_dir_all(&java_dir);
}

/// One large minified JS file with thousands of member calls on a single
/// line.  The Express probe used to validate and scan the whole file for
/// the `express` witness once per member call (quadratic); it is now
/// computed once per file.
fn bench_surface_detect_express_minified_js(c: &mut Criterion) {
    let (dir, files) = write_corpus("surf_min", 1, "js", |_| {
        let mut src = String::with_capacity(700_000);
        src.push_str("var r=function(){");
        for i in 0..9000 {
            src.push_str(&format!("o{i}.m{i}(a{i},b{i});x{i}.y{i}.z{i}(c{i});"));
        }
        src.push_str("};\n");
        src
    });
    let cfg = Config::default();
    let mut group = c.benchmark_group("surface_detect_express_minified_js");
    group.sample_size(10);
    group.bench_function("one_file", |b| {
        b.iter(|| surface_inputs_run(&files, &dir, &cfg));
    });
    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Type-fact predicates over a chained JS callee whose text embeds a whole
/// callback body (`wrap(function(){...}).then`).  The call analysis asks
/// several predicates about the same text per instruction; each used to
/// re-normalise the full string.
fn bench_type_facts_chained_callee_js(c: &mut Criterion) {
    use nyx_scanner::ssa::type_facts::{
        is_int_producing_callee, is_safe_string_producing_callee, peel_identity_suffix,
    };
    use nyx_scanner::symbol::Lang;
    let mut callee = String::from("wrap(function(){");
    for i in 0..400 {
        callee.push_str(&format!(
            "var v{i}=f{i}(a({i}),b[{i}]);if(v{i}){{g(v{i});}}"
        ));
    }
    callee.push_str("}).then");
    c.bench_function("type_facts_chained_callee_js", |b| {
        b.iter(|| {
            let callee = std::hint::black_box(callee.as_str());
            let mut hits = 0usize;
            for _ in 0..4 {
                hits += usize::from(is_int_producing_callee(Some(Lang::JavaScript), callee));
                hits += usize::from(is_safe_string_producing_callee(callee));
                hits += peel_identity_suffix(callee).len();
            }
            hits
        });
    });
}

/// Cold counterpart of `type_facts_chained_callee_js`: every iteration sees
/// a callee text the per-thread memo has never held, so each predicate pays
/// the normalisation plus the memo insert once, as a file whose long callee
/// texts each appear once or twice would.  The text is built in the batch
/// setup and excluded from the timing.
fn bench_type_facts_chained_callee_js_cold(c: &mut Criterion) {
    use nyx_scanner::ssa::type_facts::{
        is_int_producing_callee, is_safe_string_producing_callee, peel_identity_suffix,
    };
    use nyx_scanner::symbol::Lang;
    let mut serial = 0usize;
    c.bench_function("type_facts_chained_callee_js_cold", |b| {
        b.iter_batched(
            || {
                serial += 1;
                let mut callee = String::from("wrap(function(){");
                for i in 0..400 {
                    callee.push_str(&format!(
                        "var v{i}=f{serial}_{i}(a({i}),b[{i}]);if(v{i}){{g(v{i});}}"
                    ));
                }
                callee.push_str("}).then");
                callee
            },
            |callee| {
                let callee = std::hint::black_box(callee.as_str());
                let mut hits = 0usize;
                hits += usize::from(is_int_producing_callee(Some(Lang::JavaScript), callee));
                hits += usize::from(is_safe_string_producing_callee(callee));
                hits += peel_identity_suffix(callee).len();
                hits
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Wide fan-in: many sources joined through branches and loops so SSA
/// variables carry 10+ origins and every worklist join merges origin
/// sets.  Exercises `merge_origins` / `push_origin_bounded` and the
/// per-push origin-cap lookup.
fn bench_taint_many_origins_join_c(c: &mut Criterion) {
    let mut src = String::from("#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n");
    for f in 0..12 {
        src.push_str(&format!("void fan{f}(int mode, int n) {{\n"));
        for k in 0..14 {
            src.push_str(&format!("  char *s{k} = getenv(\"V{f}_{k}\");\n"));
        }
        src.push_str("  char *x = s0;\n  char buf[256];\n");
        src.push_str("  for (int i = 0; i < n; i++) {\n");
        for k in 1..14 {
            src.push_str(&format!(
                "    if (mode == {k}) {{ x = s{k}; }} else if (mode == {}) {{ x = s{}; }}\n",
                k + 20,
                (k + 3) % 14
            ));
            src.push_str(&format!(
                "    while (i < {k}) {{ x = s{}; i++; }}\n",
                (k + 5) % 14
            ));
        }
        src.push_str("  }\n  strcpy(buf, x);\n  system(x);\n}\n\n");
    }
    let bytes = src.into_bytes();
    let path = Path::new("bench_many_origins.c");
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.performance.worker_threads = Some(1);
    let _ = nyx_scanner::ast::analyse_file_fused(&bytes, path, &cfg, None, None)
        .expect("warmup analyse");
    c.bench_function("taint_many_origins_join_c", |b| {
        b.iter(|| {
            nyx_scanner::ast::analyse_file_fused(&bytes, path, &cfg, None, None)
                .expect("analyse_file_fused")
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
    bench_classify_all_sweep_go,
    bench_analyse_file_fused_large_go,
    bench_extract_authorization_model_go,
    bench_extract_authorization_model_shared_go,
    bench_gitea_route_auth_edges_go,
    bench_collect_top_level_units_go,
    bench_const_propagate_large_go,
    bench_const_propagate_wide_switch,
    bench_ssa_lower_large_go,
    bench_cfg_node_map_lookup,
    bench_global_summaries_lookup_same_lang_go,
    bench_funckey_hash_lookup,
    bench_auth_matches_name,
    bench_taint_callee_resolve_stress_go,
    bench_taint_branch_stress_go,
    bench_taint_cond_revisit_go,
    bench_cfg_build_large_go,
    bench_ast_queries_large_go,
    bench_node_text_walk_large_go,
    bench_surface_build_corpus,
    bench_surface_detect_express_minified_js,
    bench_type_facts_chained_callee_js,
    bench_type_facts_chained_callee_js_cold,
    bench_taint_many_origins_join_c,
);
criterion_main!(benches);
