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
    let graph = build_module_graph(&[r.clone()]);
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
    let graph = build_module_graph(&[r.clone()]);
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
    let graph = build_module_graph(&[r.clone()]);
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
    let graph = build_module_graph(&[r.clone()]);
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
    let graph = build_module_graph(&[r.clone()]);
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
    let graph = build_module_graph(&[r.clone()]);
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
    let graph = build_module_graph(&[r.clone()]);
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
    let graph = build_module_graph(&[r.clone()]);
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

#[test]
fn module_graph_is_cheap() {
    use std::time::Instant;

    let r = root();
    let bytes_before = approximate_rss_kib();
    let start = Instant::now();
    let graph = build_module_graph(&[r.clone()]);
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
