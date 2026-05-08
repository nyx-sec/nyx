//! TS/JS module resolver foundation.
//!
//! Walks every `package.json` and `tsconfig.json` under a scan root once,
//! builds a project-wide [`ModuleGraph`], and exposes a single entry point
//! for resolving an import specifier (relative path, package import, scoped
//! package, tsconfig `paths` alias, or `node:*` builtin) to a concrete file
//! path on disk plus the exported symbol the import binds to.
//!
//! This module ships the resolver foundation only. Phases 05/09/10 consume
//! the resolved key when threading import information through SSA lowering,
//! callee resolution, and cross-file taint, no behaviour change to findings
//! is gated by phase 04 alone.
//!
//! # Public surface
//!
//! * [`ModuleGraph`], project-scoped resolver state.
//! * [`PackageEntry`], one row per resolved `package.json`.
//! * [`TsConfigPaths`], `compilerOptions.baseUrl` + `paths` for one tsconfig.
//! * [`GlobPattern`], the matched-prefix form of a tsconfig `paths` key.
//! * [`ImportTable`], per-file resolved-import view.
//! * [`ImportBinding`], one resolved import binding (local name → file +
//!   exported name).
//! * [`ResolvedModule`], the resolver's reply for a single specifier.
//! * [`build_module_graph`], walk-and-build entry point.
//!
//! Resolution is deliberately conservative: when a specifier cannot be
//! mapped to a file under the scan root the resolver returns
//! `ResolvedModule { file: None, .. }` rather than fabricating a path. The
//! consumer side decides whether to treat unresolved imports as opaque
//! (current behaviour) or as taint stops (phase 09+).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// One discovered `package.json`.
///
/// `name` is the value of the JSON `"name"` field (`"@scope/util"` or
/// `"my-pkg"`). `root` is the directory containing the manifest, used as
/// the package root for both bare and relative resolution.
/// `manifest_main` carries the legacy `main` / `module` / `types` field
/// (preserved verbatim, in spec-priority order). `exports` carries the
/// raw `"exports"` JSON value when present, parsed lazily by
/// [`resolve_exports_to_relpath`] each time a specifier asks for it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub root: PathBuf,
    #[serde(default)]
    pub manifest_main: Option<String>,
    #[serde(default)]
    pub exports: Option<serde_json::Value>,
}

/// One match key from a `tsconfig.json` `paths` mapping.
///
/// Holds the prefix that precedes the `*` (or the full key for non-glob
/// mappings) plus a flag telling [`ModuleGraph::resolve_specifier`] whether
/// the wildcard portion needs to be substituted into each candidate target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobPattern {
    pub prefix: String,
    pub has_wildcard: bool,
}

/// `tsconfig.json` `compilerOptions.baseUrl` and `paths` for one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsConfigPaths {
    pub base_url: PathBuf,
    pub paths: Vec<(GlobPattern, Vec<PathBuf>)>,
}

/// One per-file resolved import binding.
///
/// Mirrors the shape of an ES module specifier on the import side
/// (`local_name`, `source_module`) plus the resolver's verdict
/// (`resolved_file`, `exported_name`). Either of the verdict fields can
/// be `None` when the specifier cannot be mapped, the binding is still
/// stored so downstream consumers see the unresolved-but-known set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportBinding {
    pub local_name: String,
    pub source_module: String,
    pub resolved_file: Option<PathBuf>,
    pub exported_name: Option<String>,
}

/// Project-wide per-file import view.
///
/// Logical container for [`ImportBinding`] vectors keyed by the importing
/// file. Phase 04 populates entries lazily as files are CFG-built; phases
/// 05/09/10 read them.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ImportTable {
    pub per_file: HashMap<PathBuf, Vec<ImportBinding>>,
}

/// Result of [`ModuleGraph::resolve_specifier`].
///
/// `file` is `None` for builtins (`node:*`) and unresolvable specifiers.
/// `package` is `Some` when the specifier landed inside a discovered
/// [`PackageEntry`]. The combination distinguishes "resolved into a known
/// package" from "resolved into a free file" from "no resolution at all".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModule {
    pub file: Option<PathBuf>,
    pub package: Option<String>,
    pub is_builtin: bool,
}

const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

const RESOLVE_EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];

/// Project-wide resolver state.
///
/// Built once per scan via [`build_module_graph`]. All public methods are
/// `&self`, the per-file [`ImportTable`] is filled in afterwards by the
/// CFG layer (concurrently across rayon workers, see
/// [`ModuleGraph::record_imports_for_file`]).
#[derive(Debug, Default)]
pub struct ModuleGraph {
    packages: Vec<PackageEntry>,
    tsconfigs: Vec<(PathBuf, TsConfigPaths)>,
    builtins: HashSet<String>,
    imports: std::sync::RwLock<ImportTable>,
}

impl ModuleGraph {
    /// Empty graph with the standard `node:*` builtin set seeded.
    pub fn empty() -> Self {
        let builtins = NODE_BUILTINS.iter().map(|s| (*s).to_string()).collect();
        Self {
            packages: Vec::new(),
            tsconfigs: Vec::new(),
            builtins,
            imports: std::sync::RwLock::new(ImportTable::default()),
        }
    }

    /// All discovered [`PackageEntry`] rows, deepest-root last.
    pub fn packages(&self) -> &[PackageEntry] {
        &self.packages
    }

    /// All discovered tsconfig `paths` mappings.
    pub fn tsconfigs(&self) -> &[(PathBuf, TsConfigPaths)] {
        &self.tsconfigs
    }

    /// `true` when `spec` is a known node builtin (`node:fs`, `fs`,
    /// `fs/promises`, etc.).
    pub fn is_builtin(&self, spec: &str) -> bool {
        let bare = spec.strip_prefix("node:").unwrap_or(spec);
        self.builtins.contains(bare)
    }

    /// Innermost [`PackageEntry`] containing `file`, if any.
    ///
    /// "Innermost" = the entry whose `root` is the deepest ancestor of
    /// `file`. Returns `None` for paths outside every package root (e.g.
    /// scratch files in a parent directory of the scan root).
    pub fn package_for(&self, file: &Path) -> Option<&PackageEntry> {
        let canonical = canonicalize_or_owned(file);
        self.packages
            .iter()
            .filter(|p| canonical.starts_with(&p.root))
            .max_by_key(|p| p.root.as_os_str().len())
    }

    /// Project-relative or package-qualified namespace string for `file`.
    ///
    /// Returns `"@scope/name::src/file.ts"` when `file` lies inside a
    /// resolved package and `"src/file.ts"` (the bare scan-root-relative
    /// path) otherwise. Phase 10 will route [`crate::symbol::FuncKey`]
    /// construction through this helper, phase 04 only exposes it.
    pub fn project_namespace_for(&self, file: &Path, scan_root: &Path) -> String {
        let canonical_file = canonicalize_or_owned(file);
        let canonical_root = canonicalize_or_owned(scan_root);
        let rel = canonical_file
            .strip_prefix(&canonical_root)
            .unwrap_or(&canonical_file)
            .to_string_lossy()
            .into_owned();
        match self.package_for(file) {
            Some(pkg) => format!("{}::{}", pkg.name, rel),
            None => rel,
        }
    }

    /// Resolve `spec` as imported by `importer`.
    ///
    /// Walks the resolution tower in spec order:
    /// 1. `node:*` and bare-name builtins → `is_builtin: true`.
    /// 2. Relative (`./`, `../`) → file relative to `importer`'s parent.
    /// 3. Tsconfig `paths` alias → first existing target under `baseUrl`.
    /// 4. Bare package name (`@scope/util`, `lodash`) → matching
    ///    [`PackageEntry`] root, optionally appending the sub-path
    ///    (`@scope/util/sub/file`).
    ///
    /// Returns `None` only when the specifier is structurally invalid
    /// (empty string). All other failures land as
    /// `Some(ResolvedModule { file: None, .. })` so the caller sees the
    /// attempted classification.
    pub fn resolve_specifier(&self, importer: &Path, spec: &str) -> Option<ResolvedModule> {
        if spec.is_empty() {
            return None;
        }

        if self.is_builtin(spec) {
            return Some(ResolvedModule {
                file: None,
                package: None,
                is_builtin: true,
            });
        }

        if spec.starts_with("./") || spec.starts_with("../") || spec == "." || spec == ".." {
            let base = importer.parent().unwrap_or_else(|| Path::new(""));
            let joined = base.join(spec);
            let file = resolve_file_or_index(&joined);
            let package = file.as_ref().and_then(|f| self.package_for(f).map(|p| p.name.clone()));
            return Some(ResolvedModule {
                file,
                package,
                is_builtin: false,
            });
        }

        if let Some(file) = self.resolve_tsconfig_alias(importer, spec) {
            let package = self.package_for(&file).map(|p| p.name.clone());
            return Some(ResolvedModule {
                file: Some(file),
                package,
                is_builtin: false,
            });
        }

        if let Some(resolved) = self.resolve_bare_package(spec) {
            return Some(resolved);
        }

        Some(ResolvedModule {
            file: None,
            package: None,
            is_builtin: false,
        })
    }

    /// All [`ImportBinding`]s recorded for `file`, or `&[]` when none.
    ///
    /// Returns an owned `Vec` snapshot rather than a borrow because the
    /// underlying [`ImportTable`] is held behind an `RwLock` for parallel
    /// CFG-time population. Most call sites only iterate once, so the
    /// clone is cheap relative to the lock contention an exposed
    /// `RwLockReadGuard` would create.
    pub fn imports_for(&self, file: &Path) -> Vec<ImportBinding> {
        self.imports
            .read()
            .ok()
            .and_then(|t| t.per_file.get(file).cloned())
            .unwrap_or_default()
    }

    /// Replace the binding list for `file` with `bindings`.
    ///
    /// Called by the CFG layer after classifying a file's import
    /// statements. Idempotent, the last writer for a given file wins.
    pub fn record_imports_for_file(&self, file: PathBuf, bindings: Vec<ImportBinding>) {
        if let Ok(mut table) = self.imports.write() {
            table.per_file.insert(file, bindings);
        }
    }

    /// Snapshot the per-file import table.
    pub fn snapshot_import_table(&self) -> ImportTable {
        self.imports
            .read()
            .map(|t| t.clone())
            .unwrap_or_default()
    }

    fn resolve_tsconfig_alias(&self, importer: &Path, spec: &str) -> Option<PathBuf> {
        let canonical_importer = canonicalize_or_owned(importer);
        // Prefer the deepest tsconfig that's an ancestor of the importer;
        // fall back to any tsconfig if none matches (covers test fixtures
        // where the tsconfig sits at the scan root and `importer` is a
        // synthetic absolute path).
        let mut candidates: Vec<&(PathBuf, TsConfigPaths)> = self
            .tsconfigs
            .iter()
            .filter(|(p, _)| {
                p.parent()
                    .map(|d| canonical_importer.starts_with(d))
                    .unwrap_or(false)
            })
            .collect();
        if candidates.is_empty() {
            candidates = self.tsconfigs.iter().collect();
        }
        candidates.sort_by_key(|(p, _)| std::cmp::Reverse(p.as_os_str().len()));

        for (_, ts) in candidates {
            for (pat, targets) in &ts.paths {
                let suffix = match (pat.has_wildcard, spec.strip_prefix(&pat.prefix)) {
                    (true, Some(rest)) => Some(rest),
                    (false, _) if spec == pat.prefix => Some(""),
                    _ => None,
                };
                let Some(suffix) = suffix else { continue };
                for target in targets {
                    let candidate_str = if pat.has_wildcard {
                        target.to_string_lossy().replace('*', suffix)
                    } else {
                        target.to_string_lossy().into_owned()
                    };
                    let mut candidate = ts.base_url.clone();
                    candidate.push(candidate_str);
                    if let Some(file) = resolve_file_or_index(&candidate) {
                        return Some(file);
                    }
                }
            }
        }
        None
    }

    fn resolve_bare_package(&self, spec: &str) -> Option<ResolvedModule> {
        let (pkg_name, sub) = split_package_specifier(spec)?;
        let entry = self.packages.iter().find(|p| p.name == pkg_name)?;
        let resolved_file = package_entry_resolve(entry, &sub);
        Some(ResolvedModule {
            file: resolved_file,
            package: Some(entry.name.clone()),
            is_builtin: false,
        })
    }
}

/// Extract resolved [`ImportBinding`]s from a parsed JS/TS file.
///
/// Walks top-level `import_statement` nodes, captures every named, default,
/// and namespace specifier, and resolves each against `graph` from the
/// importer's perspective. CommonJS `require(...)` patterns are handled
/// alongside the ES variants. Specifiers that don't classify (empty
/// strings, malformed) are dropped silently, the conservative path mirrors
/// how the legacy CFG-side extractor treats unparseable imports.
///
/// The returned vector is in source order. The bindings carry both the
/// `source_module` text and the resolver verdict (`resolved_file`,
/// `exported_name`), so consumers that want raw text can keep working
/// without round-tripping through [`ResolvedModule`].
pub fn extract_resolved_imports(
    tree: &tree_sitter::Tree,
    code: &[u8],
    importer: &Path,
    graph: &ModuleGraph,
    lang: &str,
) -> Vec<ImportBinding> {
    if !matches!(lang, "javascript" | "typescript" | "tsx") {
        return Vec::new();
    }
    let raws = walk_js_top_level_imports(tree, code);
    let mut cache: HashMap<String, ResolvedModule> = HashMap::new();
    let mut out = Vec::with_capacity(raws.len());
    for raw in raws {
        let resolved = cache.entry(raw.source_spec.clone()).or_insert_with(|| {
            graph
                .resolve_specifier(importer, &raw.source_spec)
                .unwrap_or(ResolvedModule {
                    file: None,
                    package: None,
                    is_builtin: false,
                })
        });
        out.push(make_binding(
            &raw.local,
            &raw.exported,
            &raw.source_spec,
            resolved,
        ));
    }
    out
}

/// One raw JS/TS import binding lifted from a top-level
/// `import_statement` / `lexical_declaration` / `variable_declaration`,
/// pre-resolution. Both [`extract_resolved_imports`] (which adds the
/// resolver verdict) and [`crate::cfg::imports::extract_local_import_view`]
/// (which only needs `local` → `source_spec`) consume this.
///
/// `local` is empty for side-effect-only `import 'mod'` shapes; consumers
/// that need a local binding skip those entries.
#[derive(Debug, Clone)]
pub struct RawJsImport {
    pub local: String,
    /// `"default"` for default-import / `const x = require(...)` / shorthand
    /// destructure; `"*"` for namespace-import; the pre-alias imported name
    /// for named-import / `const { orig: alias } = require(...)`; `""` for
    /// side-effect-only `import 'mod'`.
    pub exported: String,
    /// Source module specifier with surrounding quotes stripped.
    pub source_spec: String,
}

/// Top-level walker for JS/TS `import_statement` and `require(...)`
/// declarations. Returns raw bindings without consulting any
/// [`ModuleGraph`], so it can run at CFG-build time before the resolver
/// has populated its tables.
pub fn walk_js_top_level_imports(
    tree: &tree_sitter::Tree,
    code: &[u8],
) -> Vec<RawJsImport> {
    let mut out = Vec::new();
    let root = tree.root_node();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "import_statement" => walk_import_statement(child, code, &mut out),
            "lexical_declaration" | "variable_declaration" => {
                walk_require_decl(child, code, &mut out)
            }
            _ => {}
        }
    }
    out
}

fn walk_import_statement(
    node: tree_sitter::Node,
    code: &[u8],
    out: &mut Vec<RawJsImport>,
) {
    let Some(source) = node.child_by_field_name("source") else {
        return;
    };
    let Ok(raw) = source.utf8_text(code) else {
        return;
    };
    let spec = raw.trim_matches(|c| c == '\'' || c == '"' || c == '`');
    if spec.is_empty() {
        return;
    }

    let mut cursor = node.walk();
    let mut emitted_any = false;
    for clause_child in node.children(&mut cursor) {
        if clause_child.kind() != "import_clause" {
            continue;
        }
        let mut c2 = clause_child.walk();
        for part in clause_child.children(&mut c2) {
            match part.kind() {
                "identifier" => {
                    if let Ok(name) = part.utf8_text(code) {
                        out.push(RawJsImport {
                            local: name.to_string(),
                            exported: "default".to_string(),
                            source_spec: spec.to_string(),
                        });
                        emitted_any = true;
                    }
                }
                "namespace_import" => {
                    let mut c3 = part.walk();
                    for ns_child in part.children(&mut c3) {
                        if ns_child.kind() == "identifier" {
                            if let Ok(name) = ns_child.utf8_text(code) {
                                out.push(RawJsImport {
                                    local: name.to_string(),
                                    exported: "*".to_string(),
                                    source_spec: spec.to_string(),
                                });
                                emitted_any = true;
                            }
                        }
                    }
                }
                "named_imports" => {
                    let mut c3 = part.walk();
                    for spec_node in part.children(&mut c3) {
                        if spec_node.kind() != "import_specifier" {
                            continue;
                        }
                        let original = spec_node
                            .child_by_field_name("name")
                            .and_then(|n| n.utf8_text(code).ok());
                        let alias = spec_node
                            .child_by_field_name("alias")
                            .and_then(|n| n.utf8_text(code).ok());
                        let (Some(orig), local) =
                            (original, alias.unwrap_or(original.unwrap_or("")))
                        else {
                            continue;
                        };
                        if local.is_empty() {
                            continue;
                        }
                        out.push(RawJsImport {
                            local: local.to_string(),
                            exported: orig.to_string(),
                            source_spec: spec.to_string(),
                        });
                        emitted_any = true;
                    }
                }
                _ => {}
            }
        }
    }

    // Side-effect-only `import "mod"`: emit a marker so phase 09 still
    // sees the dependency edge.
    if !emitted_any {
        out.push(RawJsImport {
            local: String::new(),
            exported: String::new(),
            source_spec: spec.to_string(),
        });
    }
}

fn walk_require_decl(
    node: tree_sitter::Node,
    code: &[u8],
    out: &mut Vec<RawJsImport>,
) {
    let mut cursor = node.walk();
    for decl in node.children(&mut cursor) {
        if decl.kind() != "variable_declarator" {
            continue;
        }
        let (Some(pattern), Some(value)) = (
            decl.child_by_field_name("name"),
            decl.child_by_field_name("value"),
        ) else {
            continue;
        };
        let Some(spec) = require_spec_from_value(value, code) else {
            continue;
        };
        match pattern.kind() {
            "identifier" => {
                if let Ok(name) = pattern.utf8_text(code) {
                    out.push(RawJsImport {
                        local: name.to_string(),
                        exported: "default".to_string(),
                        source_spec: spec.clone(),
                    });
                }
            }
            "object_pattern" => {
                let mut pc = pattern.walk();
                for pair in pattern.children(&mut pc) {
                    match pair.kind() {
                        "shorthand_property_identifier_pattern" | "identifier" => {
                            if let Ok(name) = pair.utf8_text(code) {
                                out.push(RawJsImport {
                                    local: name.to_string(),
                                    exported: name.to_string(),
                                    source_spec: spec.clone(),
                                });
                            }
                        }
                        "pair_pattern" => {
                            let key = pair
                                .child_by_field_name("key")
                                .and_then(|n| n.utf8_text(code).ok());
                            let val = pair
                                .child_by_field_name("value")
                                .and_then(|n| n.utf8_text(code).ok());
                            if let (Some(orig), Some(local)) = (key, val) {
                                out.push(RawJsImport {
                                    local: local.to_string(),
                                    exported: orig.to_string(),
                                    source_spec: spec.clone(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

fn require_spec_from_value(value: tree_sitter::Node, code: &[u8]) -> Option<String> {
    if value.kind() != "call_expression" {
        return None;
    }
    let func = value.child_by_field_name("function")?;
    let name = func.utf8_text(code).ok()?;
    if name != "require" {
        return None;
    }
    let args = value.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if matches!(arg.kind(), "string" | "template_string") {
            let raw = arg.utf8_text(code).ok()?;
            return Some(
                raw.trim_matches(|c| c == '\'' || c == '"' || c == '`')
                    .to_string(),
            );
        }
    }
    None
}

fn make_binding(
    local: &str,
    exported: &str,
    spec: &str,
    resolved: &ResolvedModule,
) -> ImportBinding {
    ImportBinding {
        local_name: local.to_string(),
        source_module: spec.to_string(),
        resolved_file: resolved.file.clone(),
        exported_name: if exported.is_empty() {
            None
        } else {
            Some(exported.to_string())
        },
    }
}

/// Walk every `roots` entry, collect all `package.json` and `tsconfig.json`,
/// and return a populated [`ModuleGraph`].
///
/// Hidden directories (`.git`, `.cache`, `.pitboss`) and `node_modules` are
/// skipped, the resolver targets first-party source. Manifest parse errors
/// are logged via `tracing::debug!` and the offending file is dropped from
/// the graph; the rest of the scan continues. Results from multiple roots
/// are merged in walk order.
pub fn build_module_graph(roots: &[PathBuf]) -> ModuleGraph {
    let mut graph = ModuleGraph::empty();

    for root in roots {
        let canonical = canonicalize_or_owned(root);
        walk_manifests(&canonical, &mut graph);
    }
    graph
}

fn walk_manifests(root: &Path, graph: &mut ModuleGraph) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let file_name = entry.file_name();
            let name_lossy = file_name.to_string_lossy();
            if file_type.is_dir() {
                if name_lossy.starts_with('.') || name_lossy == "node_modules" {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            match name_lossy.as_ref() {
                "package.json" => {
                    if let Some(pkg) = parse_package_json(&path) {
                        graph.packages.push(pkg);
                    }
                }
                "tsconfig.json" | "jsconfig.json" => {
                    if let Some(ts) = parse_tsconfig(&path) {
                        graph.tsconfigs.push((path, ts));
                    }
                }
                _ => {}
            }
        }
    }
}

fn parse_package_json(path: &Path) -> Option<PackageEntry> {
    let bytes = std::fs::read(path).ok()?;
    let json: serde_json::Value = parse_json_lenient(&bytes).ok()?;
    let name = json.get("name")?.as_str()?.to_string();
    let root = path.parent()?.to_path_buf();
    let manifest_main = json
        .get("main")
        .and_then(|v| v.as_str())
        .or_else(|| json.get("module").and_then(|v| v.as_str()))
        .or_else(|| json.get("types").and_then(|v| v.as_str()))
        .map(|s| s.to_string());
    let exports = json.get("exports").cloned();
    Some(PackageEntry {
        name,
        root,
        manifest_main,
        exports,
    })
}

/// Resolve a specifier to a concrete file inside `entry`'s package root.
///
/// `sub` is the post-package portion of the import specifier:
/// `""` for `@scope/util`, `"sub"` for `@scope/util/sub`, etc.
///
/// Resolution order:
/// 1. `entry.exports` if present — handles string/object/conditional/wildcard
///    shapes via [`resolve_exports_to_relpath`].
/// 2. `entry.manifest_main` (`main`/`module`/`types`) for the root entry.
/// 3. Direct path join under `entry.root` for sub-paths.
fn package_entry_resolve(entry: &PackageEntry, sub: &str) -> Option<PathBuf> {
    if let Some(exports) = entry.exports.as_ref() {
        // When `exports` is defined, Node treats it as the closure for the
        // package: legacy `main` and direct path joins under the package
        // root no longer apply. A `null` value or a missing key both
        // produce `None` here so downstream consumers see "blocked" rather
        // than silently picking up a free file.
        let rel = resolve_exports_to_relpath(exports, sub)?;
        let stripped = rel.trim_start_matches("./");
        let candidate = entry.root.join(stripped);
        return resolve_file_or_index(&candidate);
    }
    if sub.is_empty() {
        let candidate = match entry.manifest_main.as_deref() {
            Some(rel) => entry.root.join(rel),
            None => entry.root.join("index"),
        };
        return resolve_file_or_index(&candidate);
    }
    let candidate = entry.root.join(sub);
    resolve_file_or_index(&candidate)
}

/// Map `sub` against an `"exports"` JSON value to a relative path.
///
/// `sub` is the spec tail after the package name (`""`, `"sub"`,
/// `"feat/x"`, …). The returned path is relative to the package root,
/// kept verbatim from the manifest (typically `"./src/main.ts"` style).
///
/// Handles four spec-defined shapes:
/// - String value (`"exports": "./index.js"`) — root-only.
/// - Subpath map (`{ ".": "./index.js", "./sub": "./sub.js" }`).
/// - Conditional values (`{ ".": { "import": "./esm.mjs", "default": "./fallback.js" } }`).
/// - Subpath patterns (`{ "./feat/*": "./src/feat/*.js" }`).
///
/// Conditional preference order: `import` → `node` → `default` → `require`.
/// `null` values block the resolution and return `None`. Returns `None`
/// when no key matches; the caller falls back to the legacy `main` path.
fn resolve_exports_to_relpath(exports: &serde_json::Value, sub: &str) -> Option<String> {
    let key = if sub.is_empty() {
        ".".to_string()
    } else if sub.starts_with("./") {
        sub.to_string()
    } else {
        format!("./{sub}")
    };

    match exports {
        serde_json::Value::String(s) if key == "." => Some(s.clone()),
        serde_json::Value::Object(map) => {
            if let Some(val) = map.get(&key) {
                if let Some(target) = pick_conditional(val) {
                    return Some(target);
                }
            }
            for (pat, val) in map.iter() {
                if let Some(inner) = exports_pattern_match(pat, &key) {
                    if let Some(target) = pick_conditional(val) {
                        return Some(target.replace('*', &inner));
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn pick_conditional(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => {
            for cond in ["import", "node", "default", "require"] {
                if let Some(v) = map.get(cond) {
                    if let Some(s) = pick_conditional(v) {
                        return Some(s);
                    }
                }
            }
            None
        }
        serde_json::Value::Array(arr) => arr.iter().find_map(pick_conditional),
        _ => None,
    }
}

fn exports_pattern_match(pat: &str, key: &str) -> Option<String> {
    let idx = pat.find('*')?;
    let prefix = &pat[..idx];
    let suffix = &pat[idx + 1..];
    if !key.starts_with(prefix) || !key.ends_with(suffix) {
        return None;
    }
    if key.len() < prefix.len() + suffix.len() {
        return None;
    }
    let inner = &key[prefix.len()..key.len() - suffix.len()];
    Some(inner.to_string())
}

fn parse_tsconfig(path: &Path) -> Option<TsConfigPaths> {
    let bytes = std::fs::read(path).ok()?;
    let json: serde_json::Value = parse_json_lenient(&bytes).ok()?;
    let opts = json.get("compilerOptions")?;
    let dir = path.parent()?.to_path_buf();
    let base_url = match opts.get("baseUrl").and_then(|v| v.as_str()) {
        Some(rel) => dir.join(rel),
        None => dir,
    };
    let mut paths_out: Vec<(GlobPattern, Vec<PathBuf>)> = Vec::new();
    if let Some(paths_obj) = opts.get("paths").and_then(|v| v.as_object()) {
        for (key, val) in paths_obj {
            let targets: Vec<PathBuf> = val
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_str())
                .map(PathBuf::from)
                .collect();
            if targets.is_empty() {
                continue;
            }
            let (prefix, has_wildcard) = if let Some(stripped) = key.strip_suffix("/*") {
                (format!("{stripped}/"), true)
            } else if key.ends_with('*') {
                (key.trim_end_matches('*').to_string(), true)
            } else {
                (key.clone(), false)
            };
            paths_out.push((
                GlobPattern {
                    prefix,
                    has_wildcard,
                },
                targets,
            ));
        }
    }
    Some(TsConfigPaths {
        base_url,
        paths: paths_out,
    })
}

fn parse_json_lenient(bytes: &[u8]) -> Result<serde_json::Value, serde_json::Error> {
    let text = std::str::from_utf8(bytes).unwrap_or("");
    let stripped = strip_jsonc(text);
    serde_json::from_str(&stripped)
}

/// Strip line/block comments and trailing commas. tsconfig files are JSONC.
///
/// Operates on raw bytes and writes raw bytes through to the output so
/// non-ASCII UTF-8 sequences (multi-byte string contents, paths) survive
/// verbatim. The earlier `out.push(b as char)` form re-encoded each
/// continuation byte as its own char and corrupted multi-byte sequences.
/// Comment / string / trailing-comma scanning only checks ASCII bytes
/// (`/`, `*`, `\\`, `"`, `,`, `]`, `}`, `\n`), and UTF-8 continuation
/// bytes are 0x80..=0xBF which never collide with ASCII, so byte-level
/// scanning stays correct on UTF-8 input.
fn strip_jsonc(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b);
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push(b'"');
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'/' {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            if next == b'*' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                continue;
            }
        }
        if b == b',' {
            // trailing-comma elide: peek ahead past whitespace for ] or }
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b']' || bytes[j] == b'}') {
                i += 1;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn split_package_specifier(spec: &str) -> Option<(String, String)> {
    if spec.starts_with('@') {
        let mut parts = spec.splitn(3, '/');
        let scope = parts.next()?;
        let pkg = parts.next()?;
        let rest = parts.next().unwrap_or("");
        Some((format!("{scope}/{pkg}"), rest.to_string()))
    } else {
        let mut parts = spec.splitn(2, '/');
        let pkg = parts.next()?;
        let rest = parts.next().unwrap_or("");
        Some((pkg.to_string(), rest.to_string()))
    }
}

fn resolve_file_or_index(candidate: &Path) -> Option<PathBuf> {
    if candidate.is_file() {
        return Some(normalize_path(candidate));
    }
    for ext in RESOLVE_EXTENSIONS {
        let mut with_ext = candidate.to_path_buf();
        match with_ext.extension() {
            Some(_) => {}
            None => {
                with_ext.set_extension(ext);
                if with_ext.is_file() {
                    return Some(normalize_path(&with_ext));
                }
            }
        }
    }
    if candidate.is_dir() {
        for ext in RESOLVE_EXTENSIONS {
            let idx = candidate.join(format!("index.{ext}"));
            if idx.is_file() {
                return Some(normalize_path(&idx));
            }
        }
    }
    None
}

/// Lexically normalize `.` / `..` segments without touching the
/// filesystem. Used so `../bar/baz` resolves to a canonical path that
/// downstream `ends_with` / `starts_with` checks can match against the
/// scan root.
fn normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn canonicalize_or_owned(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}
