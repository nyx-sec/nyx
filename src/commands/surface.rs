//! Phase 23 — `nyx surface` subcommand.
//!
//! Walks the project tree, builds a [`SurfaceMap`] from the framework
//! probes (plus any persisted data-store / external-service /
//! dangerous-local nodes from a prior indexed scan) and renders the
//! map in the format requested by the user.
//!
//! Output formats:
//!   * `text` — indented tree per entry-point, grouped by file
//!   * `json` — canonical JSON (byte-identical to the SQLite payload)
//!   * `dot`  — graphviz source, ready to pipe through `dot -Tsvg`
//!   * `svg`  — graphviz source rendered via the local `dot` binary
//!
//! The command is read-only: it never persists to SQLite and never
//! modifies the project tree.  It tries to load a previously persisted
//! map first; if none exists (no `nyx scan` ever ran, or the index was
//! cleaned) it falls back to building a fresh entry-point-only map by
//! running the framework probes against the on-disk source.
//!
//! Pass `--build` to force a full inline build that runs pass-1
//! summary extraction + call-graph construction.  That populates the
//! same DataStore / ExternalService / DangerousLocal nodes and Reaches
//! edges that an indexed scan would have persisted, at the cost of
//! parsing the project tree once (same wall-clock as `nyx index
//! build`).

use crate::ast::extract_all_summaries_from_bytes;
use crate::callgraph;
use crate::cli::SurfaceFormat;
use crate::database::index::Indexer;
use crate::errors::{NyxError, NyxResult};
use crate::summary::GlobalSummaries;
use crate::surface::{
    DataStoreKind, EdgeKind, EntryPoint, ExternalServiceKind, SurfaceMap, SurfaceNode,
    build::{SurfaceBuildInputs, build_surface_map},
};
use crate::utils::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_file_walker;
use crossbeam_channel::TryRecvError;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Top-level CLI handler.  Resolves the scan root, loads or builds a
/// [`SurfaceMap`], renders it in `format`, and writes to stdout.
///
/// When `build_inline` is `true`, the persisted SurfaceMap (if any) is
/// ignored and the full map is built by running pass-1 summary
/// extraction + call-graph construction against the on-disk source.
/// This populates DataStore / ExternalService / DangerousLocal nodes
/// and Reaches edges that the entry-points-only fallback omits.
pub fn handle(
    path: &str,
    format: SurfaceFormat,
    build_inline: bool,
    database_dir: &Path,
    config: &Config,
) -> NyxResult<()> {
    let scan_root = Path::new(path).canonicalize()?;
    let map = if build_inline {
        build_full_from_filesystem(&scan_root, config)?
    } else {
        load_or_build(&scan_root, database_dir, config)?
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match format {
        SurfaceFormat::Text => {
            out.write_all(render_text(&map, Some(&scan_root)).as_bytes())?;
        }
        SurfaceFormat::Json => {
            let mut canon = map;
            let bytes = canon
                .to_json()
                .map_err(|e| NyxError::Msg(format!("surface map JSON: {e}")))?;
            out.write_all(&bytes)?;
            out.write_all(b"\n")?;
        }
        SurfaceFormat::Dot => {
            out.write_all(render_dot(&map).as_bytes())?;
        }
        SurfaceFormat::Svg => {
            let svg = render_svg(&map)?;
            out.write_all(&svg)?;
        }
    }
    Ok(())
}

/// Load the SurfaceMap persisted under `scan_root`'s project entry, or
/// build a fresh entry-point-only map from the filesystem when no
/// indexed scan has ever populated one.
pub fn load_or_build(
    scan_root: &Path,
    database_dir: &Path,
    config: &Config,
) -> NyxResult<SurfaceMap> {
    if let Ok((project, db_path)) = get_project_info(scan_root, database_dir) {
        if db_path.exists() {
            if let Ok(pool) = Indexer::init(&db_path) {
                if let Ok(idx) = Indexer::from_pool(&project, &pool) {
                    if let Ok(Some(map)) = idx.load_surface_map() {
                        if !map.nodes.is_empty() {
                            return Ok(map);
                        }
                    }
                }
            }
        }
    }
    build_from_filesystem(scan_root, config)
}

fn build_from_filesystem(scan_root: &Path, config: &Config) -> NyxResult<SurfaceMap> {
    let files = collect_files(scan_root, config)?;
    let summaries = GlobalSummaries::new();
    let call_graph = callgraph::build_call_graph(&summaries, &[]);
    let inputs = SurfaceBuildInputs {
        files: &files,
        scan_root: Some(scan_root),
        global_summaries: &summaries,
        call_graph: &call_graph,
        config,
    };
    Ok(build_surface_map(&inputs))
}

/// Build a full SurfaceMap from source by running pass-1 summary
/// extraction inline + call-graph construction, then handing the
/// resulting [`GlobalSummaries`] + [`CallGraph`] to
/// [`build_surface_map`].  Same cost as `nyx index build` pass 1 but
/// holds nothing in SQLite.
fn build_full_from_filesystem(scan_root: &Path, config: &Config) -> NyxResult<SurfaceMap> {
    let files = collect_files(scan_root, config)?;
    let mut summaries = build_summaries_inline(&files, scan_root, config);
    summaries.install_hierarchy();
    let call_graph = callgraph::build_call_graph(&summaries, &[]);
    let inputs = SurfaceBuildInputs {
        files: &files,
        scan_root: Some(scan_root),
        global_summaries: &summaries,
        call_graph: &call_graph,
        config,
    };
    Ok(build_surface_map(&inputs))
}

/// Run pass-1 summary extraction across `files` in parallel and merge
/// the per-thread results into a single [`GlobalSummaries`].  Mirrors
/// the `scan_filesystem_with_observer` pass-1 fold/reduce shape but
/// strips out the progress / metrics / logs threading the surface
/// command does not need.
///
/// Per-file errors are swallowed so a single bad file does not kill
/// the whole map.
fn build_summaries_inline(
    files: &[PathBuf],
    scan_root: &Path,
    config: &Config,
) -> GlobalSummaries {
    let root_str = scan_root.to_string_lossy().into_owned();
    let mg = config.module_graph.as_deref();
    files
        .par_iter()
        .fold(GlobalSummaries::new, |mut local_gs, path| {
            let Ok(bytes) = std::fs::read(path) else {
                return local_gs;
            };
            let Ok((func_summaries, ssa_summaries, ssa_bodies, auth_summaries, cross_pkg)) =
                extract_all_summaries_from_bytes(&bytes, path, config, Some(scan_root))
            else {
                return local_gs;
            };
            for s in func_summaries {
                let key = s.func_key_with_resolver(Some(&root_str), mg);
                local_gs.insert(key, s);
            }
            for (key, ssa_sum) in ssa_summaries {
                local_gs.insert_ssa(key, ssa_sum);
            }
            for (key, body) in ssa_bodies {
                local_gs.insert_body(key, body);
            }
            for (key, auth_sum) in auth_summaries {
                local_gs.insert_auth(key, auth_sum);
            }
            if let Some((ns, map)) = cross_pkg {
                local_gs.insert_cross_package_imports(ns, map);
            }
            local_gs
        })
        .reduce(GlobalSummaries::new, |mut a, b| {
            a.merge(b);
            a
        })
}

fn collect_files(root: &Path, config: &Config) -> NyxResult<Vec<PathBuf>> {
    let (rx, handle) = spawn_file_walker(root, config);
    let mut out = Vec::new();
    loop {
        match rx.try_recv() {
            Ok(batch) => out.extend(batch),
            Err(TryRecvError::Empty) => match rx.recv() {
                Ok(batch) => out.extend(batch),
                Err(_) => break,
            },
            Err(TryRecvError::Disconnected) => break,
        }
    }
    let _ = handle.join();
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Text rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Produce a human-readable tree.  Files appear as top-level headers;
/// each entry-point sits under its host file with its reach summary
/// (`Reaches: …`).  Data stores / external services / dangerous locals
/// that no entry-point reaches are grouped under a trailing "Unreached"
/// section so a reviewer notices orphaned attack surface.
pub fn render_text(map: &SurfaceMap, scan_root: Option<&Path>) -> String {
    let mut out = String::new();
    if let Some(root) = scan_root {
        out.push_str(&format!("Surface map for {}\n", root.display()));
    } else {
        out.push_str("Surface map\n");
    }
    let entry_count = count_kind(map, |n| matches!(n, SurfaceNode::EntryPoint(_)));
    let ds_count = count_kind(map, |n| matches!(n, SurfaceNode::DataStore(_)));
    let es_count = count_kind(map, |n| matches!(n, SurfaceNode::ExternalService(_)));
    let dl_count = count_kind(map, |n| matches!(n, SurfaceNode::DangerousLocal(_)));
    out.push_str(&format!(
        "  {} {}, {} {}, {} {}, {} {}\n\n",
        entry_count,
        plural(entry_count, "entry-point", "entry-points"),
        ds_count,
        plural(ds_count, "data store", "data stores"),
        es_count,
        plural(es_count, "external service", "external services"),
        dl_count,
        plural(dl_count, "dangerous local", "dangerous locals"),
    ));

    if map.nodes.is_empty() {
        out.push_str("  (no entry-points or sinks detected)\n");
        return out;
    }

    let mut by_file: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (idx, node) in map.nodes.iter().enumerate() {
        by_file
            .entry(node.location().file.as_str())
            .or_default()
            .push(idx);
    }

    let mut reached: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for edge in &map.edges {
        if matches!(edge.kind, EdgeKind::Reaches) {
            reached.insert(edge.to);
        }
    }

    for (file, indices) in &by_file {
        out.push_str(&format!("{file}\n"));
        let entry_indices: Vec<usize> = indices
            .iter()
            .copied()
            .filter(|i| matches!(map.nodes[*i], SurfaceNode::EntryPoint(_)))
            .collect();
        if !entry_indices.is_empty() {
            for &ei in &entry_indices {
                let SurfaceNode::EntryPoint(ep) = &map.nodes[ei] else {
                    continue;
                };
                render_entry_point(&mut out, ep, ei as u32, map);
            }
        }
        for &i in indices {
            match &map.nodes[i] {
                SurfaceNode::DataStore(_) | SurfaceNode::ExternalService(_)
                | SurfaceNode::DangerousLocal(_) => {
                    if !entry_indices.is_empty() {
                        continue;
                    }
                    if reached.contains(&(i as u32)) {
                        continue;
                    }
                    render_node_line(&mut out, &map.nodes[i], "  ");
                }
                _ => {}
            }
        }
        out.push('\n');
    }

    // Orphans: destinations that no entry-point reaches.
    let mut orphans: Vec<usize> = Vec::new();
    for (idx, node) in map.nodes.iter().enumerate() {
        if matches!(node, SurfaceNode::EntryPoint(_)) {
            continue;
        }
        if reached.contains(&(idx as u32)) {
            continue;
        }
        // Already printed under host file when there were no entry-points;
        // suppress to avoid duplication.
        let host_has_entries = by_file
            .get(node.location().file.as_str())
            .map(|v| {
                v.iter()
                    .any(|&j| matches!(map.nodes[j], SurfaceNode::EntryPoint(_)))
            })
            .unwrap_or(false);
        if !host_has_entries {
            continue;
        }
        orphans.push(idx);
    }
    if !orphans.is_empty() {
        out.push_str("Unreached surface\n");
        for idx in orphans {
            render_node_line(&mut out, &map.nodes[idx], "  ");
        }
    }
    out
}

fn render_entry_point(out: &mut String, ep: &EntryPoint, ep_idx: u32, map: &SurfaceMap) {
    let auth = if ep.auth_required { " [auth]" } else { "" };
    out.push_str(&format!(
        "  {} {} ({:?}){}\n",
        method_str(ep.method),
        ep.route,
        ep.framework,
        auth
    ));
    out.push_str(&format!(
        "    handler: {} at {}:{}\n",
        ep.handler_name, ep.handler_location.file, ep.handler_location.line
    ));
    let mut reached: Vec<&SurfaceNode> = map
        .edges
        .iter()
        .filter(|e| e.from == ep_idx && matches!(e.kind, EdgeKind::Reaches))
        .filter_map(|e| map.nodes.get(e.to as usize))
        .collect();
    reached.sort_by(|a, b| a.location().cmp(b.location()));
    if reached.is_empty() {
        out.push_str("    reaches: (none)\n");
        return;
    }
    out.push_str("    reaches:\n");
    for node in reached {
        render_node_line(out, node, "      - ");
    }
}

fn render_node_line(out: &mut String, node: &SurfaceNode, prefix: &str) {
    match node {
        SurfaceNode::EntryPoint(ep) => {
            out.push_str(&format!(
                "{prefix}entry {} {} ({:?})\n",
                method_str(ep.method),
                ep.route,
                ep.framework
            ));
        }
        SurfaceNode::DataStore(ds) => {
            out.push_str(&format!(
                "{prefix}data-store ({}): {} [{}:{}]\n",
                ds_kind_str(ds.kind),
                ds.label,
                ds.location.file,
                ds.location.line
            ));
        }
        SurfaceNode::ExternalService(es) => {
            out.push_str(&format!(
                "{prefix}external ({}): {} [{}:{}]\n",
                es_kind_str(es.kind),
                es.label,
                es.location.file,
                es.location.line
            ));
        }
        SurfaceNode::DangerousLocal(dl) => {
            out.push_str(&format!(
                "{prefix}dangerous: {} (cap=0x{:x}) [{}:{}]\n",
                dl.function_name, dl.cap_bits, dl.location.file, dl.location.line
            ));
        }
    }
}

fn count_kind<F: Fn(&SurfaceNode) -> bool>(map: &SurfaceMap, f: F) -> usize {
    map.nodes.iter().filter(|n| f(n)).count()
}

fn plural(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn method_str(m: crate::entry_points::HttpMethod) -> &'static str {
    use crate::entry_points::HttpMethod::*;
    match m {
        GET => "GET",
        HEAD => "HEAD",
        POST => "POST",
        PUT => "PUT",
        PATCH => "PATCH",
        DELETE => "DELETE",
        OPTIONS => "OPTIONS",
    }
}

fn ds_kind_str(k: DataStoreKind) -> &'static str {
    match k {
        DataStoreKind::Sql => "sql",
        DataStoreKind::KeyValue => "key_value",
        DataStoreKind::Document => "document",
        DataStoreKind::BlobStore => "blob_store",
        DataStoreKind::Filesystem => "filesystem",
        DataStoreKind::Unknown => "unknown",
    }
}

fn es_kind_str(k: ExternalServiceKind) -> &'static str {
    match k {
        ExternalServiceKind::HttpApi => "http_api",
        ExternalServiceKind::MessageBroker => "message_broker",
        ExternalServiceKind::SearchIndex => "search_index",
        ExternalServiceKind::AuthProvider => "auth_provider",
        ExternalServiceKind::Unknown => "unknown",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DOT / SVG rendering
// ─────────────────────────────────────────────────────────────────────────────

pub fn render_dot(map: &SurfaceMap) -> String {
    let mut out = String::new();
    out.push_str("digraph nyx_surface {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [fontname=\"Helvetica\", shape=box, style=rounded];\n");
    for (i, node) in map.nodes.iter().enumerate() {
        let (label, shape, color) = match node {
            SurfaceNode::EntryPoint(ep) => (
                format!(
                    "{} {}\\n{:?}\\n{}",
                    method_str(ep.method),
                    escape_dot(&ep.route),
                    ep.framework,
                    escape_dot(&ep.handler_name),
                ),
                "box",
                if ep.auth_required { "#3aa57c" } else { "#3072c4" },
            ),
            SurfaceNode::DataStore(ds) => (
                format!("DataStore ({})\\n{}", ds_kind_str(ds.kind), escape_dot(&ds.label)),
                "cylinder",
                "#b07a18",
            ),
            SurfaceNode::ExternalService(es) => (
                format!(
                    "External ({})\\n{}",
                    es_kind_str(es.kind),
                    escape_dot(&es.label)
                ),
                "component",
                "#8b3aa5",
            ),
            SurfaceNode::DangerousLocal(dl) => (
                format!(
                    "Dangerous\\n{}\\ncap=0x{:x}",
                    escape_dot(&dl.function_name),
                    dl.cap_bits
                ),
                "octagon",
                "#c44141",
            ),
        };
        out.push_str(&format!(
            "  n{i} [label=\"{label}\", shape={shape}, color=\"{color}\", fontcolor=\"{color}\"];\n",
        ));
    }
    for edge in &map.edges {
        let style = match edge.kind {
            EdgeKind::Reaches => "solid",
            EdgeKind::Calls => "dashed",
            EdgeKind::ReadsFrom => "solid",
            EdgeKind::WritesTo => "bold",
            EdgeKind::TalksTo => "solid",
            EdgeKind::Triggers => "dotted",
            EdgeKind::AuthRequiredOn => "dotted",
        };
        out.push_str(&format!(
            "  n{} -> n{} [label=\"{:?}\", style={style}];\n",
            edge.from, edge.to, edge.kind
        ));
    }
    out.push_str("}\n");
    out
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn render_svg(map: &SurfaceMap) -> NyxResult<Vec<u8>> {
    let dot = render_dot(map);
    let mut child = Command::new("dot")
        .arg("-Tsvg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            NyxError::Msg(format!(
                "failed to spawn `dot` for SVG rendering: {e}. Install graphviz, or use `--format dot` and pipe through `dot -Tsvg` yourself."
            ))
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(dot.as_bytes())
            .map_err(|e| NyxError::Msg(format!("write DOT to dot stdin: {e}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| NyxError::Msg(format!("waiting on `dot`: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(NyxError::Msg(format!("dot exited non-zero: {stderr}")));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry_points::HttpMethod;
    use crate::surface::{
        EntryPoint, Framework, SourceLocation, SurfaceEdge, SurfaceNode,
    };

    fn flask_fixture_map() -> SurfaceMap {
        let mut map = SurfaceMap::new();
        map.nodes.push(SurfaceNode::EntryPoint(EntryPoint {
            location: SourceLocation::new("app.py", 5, 1),
            framework: Framework::Flask,
            method: HttpMethod::GET,
            route: "/users".into(),
            handler_name: "list_users".into(),
            handler_location: SourceLocation::new("app.py", 6, 1),
            auth_required: false,
        }));
        map.canonicalize();
        map
    }

    #[test]
    fn text_render_shows_entry_point() {
        let m = flask_fixture_map();
        let text = render_text(&m, None);
        assert!(text.contains("GET /users"));
        assert!(text.contains("handler: list_users"));
        assert!(text.contains("app.py"));
    }

    #[test]
    fn dot_render_emits_digraph_header() {
        let m = flask_fixture_map();
        let dot = render_dot(&m);
        assert!(dot.starts_with("digraph nyx_surface"));
        assert!(dot.contains("GET /users"));
    }

    #[test]
    fn dot_escapes_quotes_in_labels() {
        let mut m = SurfaceMap::new();
        m.nodes.push(SurfaceNode::EntryPoint(EntryPoint {
            location: SourceLocation::new("a.py", 1, 1),
            framework: Framework::Flask,
            method: HttpMethod::GET,
            route: r#"/with"quote"#.into(),
            handler_name: "h".into(),
            handler_location: SourceLocation::new("a.py", 2, 1),
            auth_required: false,
        }));
        let dot = render_dot(&m);
        assert!(dot.contains(r#"/with\"quote"#));
    }

    #[test]
    fn text_render_groups_reaches_under_entry() {
        let mut m = flask_fixture_map();
        m.nodes
            .push(SurfaceNode::DangerousLocal(crate::surface::DangerousLocal {
                location: SourceLocation::new("app.py", 12, 1),
                function_name: "eval".into(),
                cap_bits: crate::labels::Cap::CODE_EXEC.bits(),
            }));
        // Build edge after canonicalize so indices are stable.
        m.canonicalize();
        let ep_idx = m
            .nodes
            .iter()
            .position(|n| matches!(n, SurfaceNode::EntryPoint(_)))
            .unwrap() as u32;
        let dl_idx = m
            .nodes
            .iter()
            .position(|n| matches!(n, SurfaceNode::DangerousLocal(_)))
            .unwrap() as u32;
        m.edges.push(SurfaceEdge {
            from: ep_idx,
            to: dl_idx,
            kind: EdgeKind::Reaches,
        });
        m.canonicalize();
        let text = render_text(&m, None);
        assert!(text.contains("reaches:"));
        assert!(text.contains("dangerous: eval"));
    }

    #[test]
    fn build_summaries_inline_extracts_function_summaries() {
        // Establishes that the inline pass-1 path produces the same
        // `GlobalSummaries` shape that an indexed scan would have
        // persisted — at minimum, one FuncSummary per top-level
        // function in the fixture.  Without this guarantee the surface
        // build downstream falls back to entry-points-only because
        // `detect_data_stores` / `detect_external_services` /
        // `detect_dangerous_locals` walk the summaries map.
        let td = tempfile::tempdir().unwrap();
        let project_dir = td.path();
        std::fs::write(
            project_dir.join("app.py"),
            "from flask import Flask, request\n\
             app = Flask(__name__)\n\
             \n\
             @app.route('/run')\n\
             def run():\n\
                 cmd = request.args.get('cmd')\n\
                 return str(eval(cmd))\n\
             \n\
             def helper(x):\n\
                 return eval(x)\n",
        )
        .unwrap();

        let cfg = Config::default();
        let canon = project_dir.canonicalize().unwrap();
        let files = collect_files(&canon, &cfg).unwrap();
        let summaries = build_summaries_inline(&files, &canon, &cfg);
        let names: Vec<String> = summaries
            .iter()
            .map(|(k, _)| k.qualified_name())
            .collect();
        assert!(
            names.iter().any(|n| n.ends_with("run")),
            "summaries should contain `run`, got {names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("helper")),
            "summaries should contain `helper`, got {names:?}"
        );
    }

    #[test]
    fn build_full_from_filesystem_walks_pass1_pipeline() {
        // End-to-end smoke for `surface::handle(..., build=true)`: the
        // inline-build path must produce a non-empty SurfaceMap on a
        // project with a recognisable framework route.  Equivalent to
        // running `nyx surface --build .` on a single-file Flask app.
        let td = tempfile::tempdir().unwrap();
        let project_dir = td.path();
        std::fs::write(
            project_dir.join("app.py"),
            "from flask import Flask, request\n\
             app = Flask(__name__)\n\
             \n\
             @app.route('/run')\n\
             def run():\n\
                 cmd = request.args.get('cmd')\n\
                 return str(eval(cmd))\n",
        )
        .unwrap();

        let cfg = Config::default();
        let canon = project_dir.canonicalize().unwrap();
        let map = build_full_from_filesystem(&canon, &cfg).expect("inline build succeeds");

        let has_entry = map
            .nodes
            .iter()
            .any(|n| matches!(n, SurfaceNode::EntryPoint(_)));
        assert!(has_entry, "Flask /run route should be detected");
    }

    #[test]
    fn build_from_filesystem_entry_points_only_runs_with_empty_summaries() {
        // Locks in the fallback contract: `build_from_filesystem` runs
        // framework probes against an empty `GlobalSummaries` and
        // produces only entry-point nodes.  Any future change that
        // accidentally widens the fallback to populate sinks should
        // either ship through `--build` or update this test.
        let td = tempfile::tempdir().unwrap();
        let project_dir = td.path();
        std::fs::write(
            project_dir.join("app.py"),
            "from flask import Flask\n\
             app = Flask(__name__)\n\
             \n\
             @app.route('/run')\n\
             def run():\n\
                 return 'ok'\n",
        )
        .unwrap();

        let cfg = Config::default();
        let canon = project_dir.canonicalize().unwrap();
        let map = build_from_filesystem(&canon, &cfg).expect("fallback build succeeds");

        // Entry point should still appear (framework probes run in the
        // fallback path too).
        assert!(
            map.nodes
                .iter()
                .any(|n| matches!(n, SurfaceNode::EntryPoint(_))),
            "Flask route should land via framework probe"
        );
        // No DataStore / ExternalService / DangerousLocal because the
        // fallback path feeds an empty GlobalSummaries to the detectors.
        let non_entry = map.nodes.iter().any(|n| {
            matches!(
                n,
                SurfaceNode::DataStore(_)
                    | SurfaceNode::ExternalService(_)
                    | SurfaceNode::DangerousLocal(_)
            )
        });
        assert!(
            !non_entry,
            "entry-points-only fallback should not produce non-entry nodes"
        );
    }
}
