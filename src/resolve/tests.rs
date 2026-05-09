//! Phase-04 resolver tests.
//!
//! Six specifier shapes (relative, parent-relative, scoped package,
//! tsconfig path alias, node builtin, missing) plus a memory-ceiling
//! guard. Each test sets up a synthetic tree under
//! `tests/fixtures/resolver/` (or a `tempfile::TempDir` for the cheap
//! ceiling test), constructs a [`ModuleGraph`] via [`build_module_graph`],
//! and asserts the resolver verdict.

use super::*;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/resolver");
    p
}

fn root() -> PathBuf {
    let r = fixture_root();
    if r.exists() {
        r.canonicalize().unwrap_or(r)
    } else {
        r
    }
}

#[test]
fn resolves_relative_specifier() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "./foo")
        .expect("relative spec must classify");
    let file = resolved.file.expect("./foo must resolve");
    assert!(
        file.ends_with("apps/web/src/foo.ts"),
        "unexpected resolution: {}",
        file.display()
    );
    assert!(!resolved.is_builtin);
}

#[test]
fn resolves_parent_relative_specifier() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "../bar/baz")
        .expect("../bar/baz must classify");
    let file = resolved.file.expect("../bar/baz must resolve");
    assert!(
        file.ends_with("apps/web/bar/baz.ts"),
        "unexpected resolution: {}",
        file.display()
    );
}

#[test]
fn resolves_scoped_package_import() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "@scope/util")
        .expect("@scope/util must classify");
    assert_eq!(resolved.package.as_deref(), Some("@scope/util"));
    let file = resolved.file.expect("@scope/util must resolve to a file");
    assert!(
        file.ends_with("packages/util/src/index.ts")
            || file.ends_with("packages/util/index.ts"),
        "unexpected resolution: {}",
        file.display()
    );
}

#[test]
fn resolves_tsconfig_path_alias() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "@/lib/x")
        .expect("@/lib/x must classify");
    let file = resolved.file.expect("@/lib/x must resolve");
    assert!(
        file.ends_with("apps/web/src/lib/x.ts"),
        "unexpected resolution: {}",
        file.display()
    );
}

#[test]
fn classifies_node_builtin_specifier() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "node:fs/promises")
        .expect("node:fs/promises must classify");
    assert!(resolved.is_builtin);
    assert!(resolved.file.is_none());
    assert!(resolved.package.is_none());

    let bare = graph
        .resolve_specifier(&importer, "fs")
        .expect("bare 'fs' must classify");
    assert!(bare.is_builtin);
}

#[test]
fn missing_module_returns_none_resolved_file() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "no-such-package")
        .expect("non-empty spec must classify");
    assert!(!resolved.is_builtin);
    assert!(resolved.file.is_none(), "missing module must not resolve");
    assert!(resolved.package.is_none());
}

#[test]
fn package_for_returns_innermost_match() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let inner = r.join("packages/util/src/index.ts");
    let outer_pkg = graph
        .package_for(&inner)
        .expect("file under packages/util belongs to a package");
    assert_eq!(outer_pkg.name, "@scope/util");

    let app_file = r.join("apps/web/src/index.ts");
    let web_pkg = graph
        .package_for(&app_file)
        .expect("file under apps/web belongs to a package");
    assert_eq!(web_pkg.name, "web-app");
}

#[test]
fn project_namespace_prefixes_when_in_package() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let in_pkg = r.join("packages/util/src/index.ts");
    let ns = graph.project_namespace_for(&in_pkg, &r);
    assert!(
        ns.starts_with("@scope/util::"),
        "expected package-prefixed namespace, got {ns}"
    );

    let outside = std::env::temp_dir().join("nyx-resolver-outside.ts");
    let plain = graph.project_namespace_for(&outside, &r);
    assert!(!plain.contains("::"), "outside-package namespace must be plain: {plain}");
}

/// `"exports"."."` conditional map: `import` branch wins over `default`,
/// and the legacy `main` field is shadowed when exports resolve.
#[test]
fn resolves_exports_root_conditional() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "@scope/exports-pkg")
        .expect("@scope/exports-pkg must classify");
    assert_eq!(resolved.package.as_deref(), Some("@scope/exports-pkg"));
    let file = resolved.file.expect("@scope/exports-pkg must resolve");
    assert!(
        file.ends_with("exports-pkg/src/main.ts"),
        "expected import-branch main.ts, got {}",
        file.display()
    );
}

/// Exact subpath key (`"./sub": "./src/sub.ts"`) resolves before any
/// pattern fallback would fire.
#[test]
fn resolves_exports_exact_subpath() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "@scope/exports-pkg/sub")
        .expect("subpath spec must classify");
    let file = resolved.file.expect("./sub must resolve");
    assert!(
        file.ends_with("exports-pkg/src/sub.ts"),
        "unexpected resolution: {}",
        file.display()
    );
}

/// Wildcard pattern (`"./feat/*": "./src/feat/*.ts"`) substitutes the
/// matched tail into the target.
#[test]
fn resolves_exports_wildcard_subpath() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "@scope/exports-pkg/feat/widget")
        .expect("wildcard subpath must classify");
    let file = resolved.file.expect("./feat/widget must resolve");
    assert!(
        file.ends_with("exports-pkg/src/feat/widget.ts"),
        "unexpected resolution: {}",
        file.display()
    );
}

/// `null` value blocks the subpath: resolver returns no file rather than
/// falling back to a direct path join.
#[test]
fn exports_null_blocks_subpath() {
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let resolved = graph
        .resolve_specifier(&importer, "@scope/exports-pkg/blocked")
        .expect("blocked spec must classify");
    assert!(
        resolved.file.is_none(),
        "null exports value must not resolve, got {:?}",
        resolved.file
    );
}

#[test]
fn module_graph_is_cheap() {
    use std::time::Instant;

    let r = root();
    let bytes_before = approximate_rss_kib();
    let start = Instant::now();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let elapsed = start.elapsed();
    let bytes_after = approximate_rss_kib();

    assert!(
        elapsed.as_millis() < 50,
        "build_module_graph took {}ms (>50ms ceiling)",
        elapsed.as_millis()
    );

    let delta_kib = bytes_after.saturating_sub(bytes_before);
    assert!(
        delta_kib < 10 * 1024,
        "build_module_graph added {delta_kib} KiB RSS (>10 MiB ceiling)"
    );

    assert!(!graph.packages().is_empty(), "fixture tree must have packages");
}

/// Parse a TypeScript file with tree-sitter and run
/// [`extract_resolved_imports`] against it.  Tests pull this through to
/// keep the parsing setup in one place.
fn extract_imports_for(file: &std::path::Path, graph: &ModuleGraph) -> Vec<ImportBinding> {
    let bytes = std::fs::read(file).expect("read fixture file");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter::Language::from(
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        ))
        .expect("load TS grammar");
    let tree = parser.parse(&bytes, None).expect("parse fixture");
    extract_resolved_imports(&tree, &bytes, file, graph, "typescript")
}

#[test]
fn parses_imports_from_fixture_file() {
    // Verify `extract_resolved_imports` lifts the same four binding shapes
    // that `tests/fixtures/resolver/apps/web/src/index.ts` exercises:
    // relative, parent-relative, scoped package, tsconfig path alias, plus
    // the `node:fs/promises` builtin.  Phases 09/10 thread these bindings
    // through cross-file taint, so the parsed-file integration path must
    // produce the rows the resolver tests already cover via
    // `resolve_specifier`.
    let r = root();
    let graph = build_module_graph(std::slice::from_ref(&r));
    let importer = r.join("apps/web/src/index.ts");
    let bindings = extract_imports_for(&importer, &graph);

    let by_local: std::collections::HashMap<&str, &ImportBinding> = bindings
        .iter()
        .map(|b| (b.local_name.as_str(), b))
        .collect();

    // `import { foo } from "./foo"` — relative.
    let foo = by_local.get("foo").expect("foo binding present");
    assert_eq!(foo.source_module, "./foo");
    assert_eq!(foo.exported_name.as_deref(), Some("foo"));
    let foo_file = foo.resolved_file.as_ref().expect("./foo resolves");
    assert!(
        foo_file.ends_with("apps/web/src/foo.ts"),
        "foo unexpected: {}",
        foo_file.display()
    );

    // `import { baz } from "../bar/baz"` — parent-relative.
    let baz = by_local.get("baz").expect("baz binding present");
    assert_eq!(baz.source_module, "../bar/baz");
    let baz_file = baz.resolved_file.as_ref().expect("../bar/baz resolves");
    assert!(
        baz_file.ends_with("apps/web/bar/baz.ts"),
        "baz unexpected: {}",
        baz_file.display()
    );

    // `import { util } from "@scope/util"` — scoped package.
    let util = by_local.get("util").expect("util binding present");
    assert_eq!(util.source_module, "@scope/util");
    assert!(
        util.resolved_file.is_some(),
        "@scope/util must resolve to a file"
    );

    // `import { x } from "@/lib/x"` — tsconfig path alias.
    let x = by_local.get("x").expect("x binding present");
    assert_eq!(x.source_module, "@/lib/x");
    let x_file = x.resolved_file.as_ref().expect("@/lib/x resolves");
    assert!(
        x_file.ends_with("apps/web/src/lib/x.ts"),
        "x unexpected: {}",
        x_file.display()
    );

    // `import { promises as fs } from "node:fs/promises"` — node builtin.
    // Local-name binding must use the alias `fs`, not the original `promises`.
    let fs = by_local.get("fs").expect("fs alias binding present");
    assert_eq!(fs.source_module, "node:fs/promises");
    assert_eq!(fs.exported_name.as_deref(), Some("promises"));
    assert!(
        fs.resolved_file.is_none(),
        "node:* builtin must not carry a resolved file"
    );
}

/// Best-effort RSS reader. Returns 0 on any failure, the test only uses
/// the delta and treats "0 → 0" as "below ceiling".
fn approximate_rss_kib() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .and_then(|n| n.parse::<u64>().ok())
                    })
            })
            .unwrap_or(0)
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok();
        output
            .and_then(|o| {
                String::from_utf8(o.stdout)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
            })
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}
