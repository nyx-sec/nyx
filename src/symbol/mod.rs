//! Core language and function identity types.
//!
//! [`Lang`] is the 10-language enum (Rust, C, C++, Java, Go, PHP, Python,
//! Ruby, TypeScript, JavaScript). [`FuncKey`] is the canonical cross-file
//! function identity: name, arity, language, container (class/struct/module),
//! and an optional disambiguator for overloaded functions.
//!
//! [`FuncKey`] is the node type in the call graph and the lookup key in
//! [`crate::summary::GlobalSummaries`]. [`FuncKind`] distinguishes constructors,
//! methods, closures, and free functions so callers can apply language-specific
//! resolution heuristics.

use rustc_hash::FxHasher;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::Path;

/// Supported source-code languages.
///
/// `Default` is provided only so that [`FuncKey`] can derive `Default` for
/// test ergonomics, production code always constructs a `Lang` explicitly
/// (via `from_slug` / `from_extension`).  `Rust` was chosen as the default
/// purely because it is the host language of the scanner; tests that rely
/// on lang-specific behaviour should set `lang` explicitly, not rely on the
/// default.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    Rust,
    C,
    Cpp,
    Java,
    Go,
    Php,
    Python,
    Ruby,
    TypeScript,
    JavaScript,
}

impl Lang {
    /// Whether a call may supply fewer arguments than the callee declares
    /// (default-valued or optional parameters).  Java, C, Go and Rust have
    /// no such calls, so an arity mismatch there names a different overload
    /// or an unrelated function (`Base64.decode(s)` is not the same-file
    /// `decode(s, loader)`).
    pub fn allows_under_application(self) -> bool {
        matches!(
            self,
            Lang::Python | Lang::Ruby | Lang::Php | Lang::JavaScript | Lang::TypeScript | Lang::Cpp
        )
    }

    /// Parse a language slug (as returned by `lang_for_path`) into a `Lang`.
    pub fn from_slug(s: &str) -> Option<Lang> {
        match s {
            "rust" => Some(Lang::Rust),
            "c" => Some(Lang::C),
            "cpp" => Some(Lang::Cpp),
            "java" => Some(Lang::Java),
            "go" => Some(Lang::Go),
            "php" => Some(Lang::Php),
            "python" => Some(Lang::Python),
            "ruby" => Some(Lang::Ruby),
            "typescript" | "ts" => Some(Lang::TypeScript),
            "javascript" | "js" => Some(Lang::JavaScript),
            _ => None,
        }
    }

    /// Derive `Lang` from a file extension (e.g. `"rs"`, `"py"`).
    ///
    /// Mirrors the extension→language mapping in `ast::lang_for_path()` so that
    /// callers outside `ast` can obtain a `Lang` from a path without needing a
    /// `FuncSummary`. Match is case-insensitive (ASCII).
    ///
    /// Extension coverage is intentionally broader than the tree-sitter loader
    /// in `ast::lang_for_path` because this function is consumed by the
    /// dynamic verifier, which must classify *every* finding-bearing path so
    /// that spec derivation does not collapse on idiomatic file extensions
    /// like `.cjs`, `.mts`, `.pyi`, or `.kts`. JVM-family `.kt` / `.kts` map
    /// to [`Lang::Java`] because the spec/toolchain layer is JVM-aware even
    /// where the tree-sitter grammar is not.
    pub fn from_extension(ext: &str) -> Option<Lang> {
        let lower = ext.to_ascii_lowercase();
        match lower.as_str() {
            "rs" => Some(Lang::Rust),
            "c" => Some(Lang::C),
            "cpp" | "cc" | "cxx" | "c++" | "hpp" | "hxx" | "hh" | "h++" => Some(Lang::Cpp),
            // Java family. `.kt` / `.kts` are Kotlin (JVM); the dynamic spec
            // layer treats them as Java for toolchain selection purposes.
            "java" | "kt" | "kts" => Some(Lang::Java),
            "go" => Some(Lang::Go),
            "php" => Some(Lang::Php),
            // `.pyi` are Python stub files; spec derivation accepts them so
            // typed-stub-only entry points still register a language.
            "py" | "pyi" => Some(Lang::Python),
            // `.mts` / `.cts` are TypeScript module-form (ES module / CommonJS).
            "ts" | "tsx" | "mts" | "cts" => Some(Lang::TypeScript),
            // `.mjs` / `.cjs` are JavaScript module-form. `.jsx` is React JSX.
            "js" | "jsx" | "mjs" | "cjs" => Some(Lang::JavaScript),
            "rb" => Some(Lang::Ruby),
            _ => None,
        }
    }

    /// Probe a path's language using extension first, then a shebang line on
    /// `head_bytes`, then a content-byte heuristic on the first 200 bytes.
    ///
    /// `head_bytes` should be the first N bytes of the file (200 is plenty;
    /// callers may pass more). Empty / unreadable files return `None`.
    ///
    /// Order:
    /// 1. [`Lang::from_extension`] on the path's extension — fast path.
    /// 2. Shebang inspection. Common interpreter aliases are recognised:
    ///    `python` / `python3` → [`Lang::Python`], `node` / `nodejs` / `deno`
    ///    / `bun` → [`Lang::JavaScript`], `ruby` → [`Lang::Ruby`], `php` →
    ///    [`Lang::Php`]. `/usr/bin/env <interp>` and direct
    ///    `/usr/bin/<interp>` paths both work.
    /// 3. Content-byte syntactic sniff: line-prefix matches on the first 200
    ///    bytes (`<?php`, `package main`, Java `package …;`, `fn main`, etc.).
    ///    The sniff stands in for a full tree-sitter parse — it is cheaper
    ///    and covers the verifier's failure modes without paying the cost of
    ///    loading every grammar for every extensionless file.
    ///
    /// Used by [`crate::dynamic::spec`] so spec derivation no longer rejects
    /// CLI entry points and other extensionless / non-canonical files.
    pub fn from_path_or_content(path: &Path, head_bytes: &[u8]) -> Option<Lang> {
        if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && let Some(lang) = Self::from_extension(ext)
        {
            return Some(lang);
        }
        if let Some(lang) = lang_from_shebang(head_bytes) {
            return Some(lang);
        }
        sniff_content_lang(head_bytes)
    }

    /// Canonical slug string for this language.
    pub fn as_str(&self) -> &'static str {
        match self {
            Lang::Rust => "rust",
            Lang::C => "c",
            Lang::Cpp => "cpp",
            Lang::Java => "java",
            Lang::Go => "go",
            Lang::Php => "php",
            Lang::Python => "python",
            Lang::Ruby => "ruby",
            Lang::TypeScript => "typescript",
            Lang::JavaScript => "javascript",
        }
    }
}

impl fmt::Display for Lang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The structural role a function plays in its source.
///
/// Used alongside `container` and `disambig` to distinguish same-name
/// definitions.  Deserialization falls back to `Function` so old JSON
/// loads cleanly.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuncKind {
    /// Free/top-level function (Rust `fn`, Go `func`, Python module-level `def`).
    #[default]
    Function,
    /// Method bound to a class / impl / struct / interface receiver.
    Method,
    /// Constructor (`__init__`, `new`, class constructor, Java `<init>`).
    Constructor,
    /// Anonymous / closure / lambda / arrow function.
    Closure,
    /// Getter (property getter, Ruby `attr_reader` style).
    Getter,
    /// Setter (property setter, Ruby `attr_writer` style).
    Setter,
    /// Implicit top-level / module body ("main script").
    TopLevel,
}

impl FuncKind {
    /// Short slug for display / logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            FuncKind::Function => "fn",
            FuncKind::Method => "method",
            FuncKind::Constructor => "ctor",
            FuncKind::Closure => "closure",
            FuncKind::Getter => "getter",
            FuncKind::Setter => "setter",
            FuncKind::TopLevel => "toplevel",
        }
    }

    /// Parse a kind slug (as written by `as_str`) back into a `FuncKind`.
    /// Unrecognized slugs fall back to `Function` to keep round-trips lenient.
    pub fn from_slug(s: &str) -> FuncKind {
        match s {
            "fn" => FuncKind::Function,
            "method" => FuncKind::Method,
            "ctor" => FuncKind::Constructor,
            "closure" => FuncKind::Closure,
            "getter" => FuncKind::Getter,
            "setter" => FuncKind::Setter,
            "toplevel" => FuncKind::TopLevel,
            _ => FuncKind::Function,
        }
    }
}

/// Uniquely identifies a function across the entire project.
///
/// Identity is a 6-tuple: `(lang, namespace, container, name, arity, disambig)`
/// plus a structural `kind` tag.  Every field is deliberately narrow so
/// legitimately-distinct definitions never collide:
///
/// * `lang`, prevents cross-language aliasing.
/// * `namespace`, project-relative source file path.
/// * `container`, enclosing class / impl / module / namespace / outer function
///   (qualified with `::` for nested containers).  Empty string for free
///   top-level functions.
/// * `name`, leaf identifier as written in source.
/// * `arity`, parameter count (including `self`/`this`) for languages that
///   discriminate by arity.  `None` for unknown.
/// * `disambig`, numeric discriminator for same-name definitions in the same
///   container (closure byte offset, nested-function occurrence index).
///   `None` for the common case of a single definition.
/// * `kind`, structural role (see [`FuncKind`]).  Separates e.g. a getter
///   named `size` from a method `size()`.
///
/// Backward-compat: `container`, `disambig`, and `kind` all have serde
/// defaults, so JSON summaries written by the old identity model still
/// deserialise cleanly and land on `FuncKind::Function` with empty
/// container/disambig.
/// # Precomputed identity hash (perfhunt session-0012, 2026-07-14)
///
/// `FuncKey` is the single most-hashed entity in the engine: it keys the
/// cross-file callee indices (`by_key`, `ssa_by_key`, `bodies_by_key`,
/// `auth_by_key`), the SCC/topo changed-key sets, and every taint-local
/// `HashMap<FuncKey, _>`.  A derived `Hash` re-walked all bytes of the three
/// `String` identity fields on every lookup — measured 44.7% of all SipHash
/// self-time (~3.8% active CPU) on mattermost.  We now cache a `u64` FxHash of
/// the seven identity fields, computed once at construction, and the manual
/// `Hash` impl writes that single `u64`: `O(identity len)` → `O(1)` per hash.
///
/// ## Soundness invariant
///
/// The cached `hash` MUST stay consistent with the seven identity fields.  It
/// is recomputed at every construction path ([`FuncKey::from_parts`],
/// [`FuncKey::new_function`], `Default`, serde `Deserialize`) and after any
/// identity mutation via the [`FuncKey::set_namespace`] /
/// [`FuncKey::set_disambig`] / [`FuncKey::set_arity`] setters or the explicit
/// [`FuncKey::recompute_hash`].  The `hash` field is **private** so the only
/// way to obtain a value is through a constructor — a struct literal outside
/// this module fails to compile, which turns "forgot to recompute" from a
/// silent bucket-collision perf bug into a compile error.  In unit-test builds
/// (`cfg(test)`) the `Hash` impl `assert_eq!`s the cache against a fresh
/// recompute, so any stale mutation panics loudly under the test suite.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(into = "FuncKeyData", from = "FuncKeyData")]
pub struct FuncKey {
    pub lang: Lang,
    /// Project-relative file path (e.g. `"src/lib.rs"`).
    pub namespace: String,
    /// Enclosing container path (class / impl / module / nested function).
    /// Empty for free top-level functions.  Segments joined with `::`.
    pub container: String,
    pub name: String,
    pub arity: Option<usize>,
    /// Numeric discriminator for same-name siblings (closures, duplicate defs).
    /// Typically the function node's start byte offset.
    pub disambig: Option<u32>,
    /// Structural role, Function, Method, Constructor, Closure, etc.
    pub kind: FuncKind,
    /// Precomputed FxHash of the seven identity fields above.  Never
    /// serialized (see `FuncKeyData`); recomputed on load.  Kept in sync by
    /// [`FuncKey::recompute_hash`] — see the type-level soundness note.
    hash: u64,
}

/// Wire form of [`FuncKey`] — the seven identity fields, no cached `hash`.
///
/// `FuncKey` serializes through this (`#[serde(into/from)]`) so the on-disk /
/// on-wire JSON is byte-for-byte identical to the old derived form (same field
/// names, same `#[serde(default)]` back-compat), and the cached `hash` is
/// recomputed on deserialize rather than persisted.  This keeps existing
/// SQLite summary blobs loadable without a schema bump.
#[derive(Serialize, Deserialize)]
struct FuncKeyData {
    lang: Lang,
    namespace: String,
    #[serde(default)]
    container: String,
    name: String,
    arity: Option<usize>,
    #[serde(default)]
    disambig: Option<u32>,
    #[serde(default)]
    kind: FuncKind,
}

impl From<FuncKeyData> for FuncKey {
    fn from(d: FuncKeyData) -> Self {
        FuncKey::from_parts(
            d.lang,
            d.namespace,
            d.container,
            d.name,
            d.arity,
            d.disambig,
            d.kind,
        )
    }
}

impl From<FuncKey> for FuncKeyData {
    fn from(k: FuncKey) -> Self {
        FuncKeyData {
            lang: k.lang,
            namespace: k.namespace,
            container: k.container,
            name: k.name,
            arity: k.arity,
            disambig: k.disambig,
            kind: k.kind,
        }
    }
}

impl Hash for FuncKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Integrity check, unit-test builds only (`cfg(test)`): the cache must
        // equal a fresh recompute.  A mismatch means an identity field was
        // mutated without going through a setter / `recompute_hash`.  Scoped to
        // `cfg(test)` so the per-hash recompute never runs on the release
        // binary, the dev binary, integration scans, or benchmarks — only the
        // lib unit tests, which directly exercise every mutation path.
        #[cfg(test)]
        assert_eq!(
            self.hash,
            FuncKey::compute_hash(
                self.lang,
                &self.namespace,
                &self.container,
                &self.name,
                self.arity,
                self.disambig,
                self.kind,
            ),
            "FuncKey identity hash is stale — a field was mutated without recompute_hash()"
        );
        state.write_u64(self.hash);
    }
}

impl PartialEq for FuncKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // Fast reject on the precomputed hash: equal identity implies equal
        // hash, so unequal hash implies unequal identity.  The field
        // comparison then confirms (guards the rare 64-bit collision).
        self.hash == other.hash
            && self.lang == other.lang
            && self.arity == other.arity
            && self.disambig == other.disambig
            && self.kind == other.kind
            && self.name == other.name
            && self.container == other.container
            && self.namespace == other.namespace
    }
}

impl Eq for FuncKey {}

impl Default for FuncKey {
    fn default() -> Self {
        FuncKey::from_parts(
            Lang::default(),
            String::new(),
            String::new(),
            String::new(),
            None,
            None,
            FuncKind::default(),
        )
    }
}

impl FuncKey {
    /// Deterministic FxHash of the seven identity fields, in a fixed order.
    ///
    /// FxHash (not SipHash) so the precompute is cheap and stable across
    /// processes — a key reconstructed from a persisted summary hashes
    /// identically to a freshly-analysed one.  The order here is the single
    /// source of truth: `recompute_hash`, `from_parts`, and the debug integrity
    /// check in `Hash` all route through this function.
    #[inline]
    fn compute_hash(
        lang: Lang,
        namespace: &str,
        container: &str,
        name: &str,
        arity: Option<usize>,
        disambig: Option<u32>,
        kind: FuncKind,
    ) -> u64 {
        let mut h = FxHasher::default();
        lang.hash(&mut h);
        namespace.hash(&mut h);
        container.hash(&mut h);
        name.hash(&mut h);
        arity.hash(&mut h);
        disambig.hash(&mut h);
        kind.hash(&mut h);
        h.finish()
    }

    /// Construct a fully-specified key, computing the cached identity hash.
    /// The canonical constructor: every other construction path (including
    /// `Default` and serde `Deserialize`) funnels through here so the cache is
    /// always populated.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        lang: Lang,
        namespace: impl Into<String>,
        container: impl Into<String>,
        name: impl Into<String>,
        arity: Option<usize>,
        disambig: Option<u32>,
        kind: FuncKind,
    ) -> Self {
        let namespace = namespace.into();
        let container = container.into();
        let name = name.into();
        let hash =
            FuncKey::compute_hash(lang, &namespace, &container, &name, arity, disambig, kind);
        FuncKey {
            lang,
            namespace,
            container,
            name,
            arity,
            disambig,
            kind,
            hash,
        }
    }

    /// Recompute and store the cached identity hash from the current fields.
    /// Call after any direct mutation of an identity field that does not go
    /// through a setter (see the type-level soundness note).
    #[inline]
    pub fn recompute_hash(&mut self) {
        self.hash = FuncKey::compute_hash(
            self.lang,
            &self.namespace,
            &self.container,
            &self.name,
            self.arity,
            self.disambig,
            self.kind,
        );
    }

    /// Set `namespace`, keeping the cached hash consistent.
    #[inline]
    pub fn set_namespace(&mut self, namespace: impl Into<String>) {
        self.namespace = namespace.into();
        self.recompute_hash();
    }

    /// Set `disambig`, keeping the cached hash consistent.
    #[inline]
    pub fn set_disambig(&mut self, disambig: Option<u32>) {
        self.disambig = disambig;
        self.recompute_hash();
    }

    /// Set `arity`, keeping the cached hash consistent.
    #[inline]
    pub fn set_arity(&mut self, arity: Option<usize>) {
        self.arity = arity;
        self.recompute_hash();
    }

    /// Construct a plain free-function key (no container, no disambig).
    /// Kept as a convenience for call sites and tests that do not need the
    /// extra discriminators.
    pub fn new_function(
        lang: Lang,
        namespace: impl Into<String>,
        name: impl Into<String>,
        arity: Option<usize>,
    ) -> Self {
        FuncKey::from_parts(
            lang,
            namespace,
            String::new(),
            name,
            arity,
            None,
            FuncKind::Function,
        )
    }

    /// Fully-qualified name like `"Class::method"` or just `"func"` for free
    /// functions.  Used for diagnostics and container-aware callee matching.
    pub fn qualified_name(&self) -> String {
        if self.container.is_empty() {
            self.name.clone()
        } else {
            format!("{}::{}", self.container, self.name)
        }
    }
}

impl fmt::Display for FuncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::", self.lang, self.namespace)?;
        if !self.container.is_empty() {
            write!(f, "{}::", self.container)?;
        }
        write!(f, "{}", self.name)?;
        if let Some(a) = self.arity {
            write!(f, "/{a}")?;
        }
        if let Some(d) = self.disambig {
            write!(f, "#{d}")?;
        }
        if self.kind != FuncKind::Function {
            write!(f, "[{}]", self.kind.as_str())?;
        }
        Ok(())
    }
}

/// Strip `root` prefix from `abs_path` to produce a stable project-relative path.
///
/// Falls back to the full path if stripping fails (e.g. in tests with synthetic paths).
pub fn normalize_namespace(abs_path: &str, root: Option<&str>) -> String {
    if let Some(r) = root {
        let r = r.trim_end_matches('/');
        if let Some(rest) = abs_path.strip_prefix(r) {
            return rest.trim_start_matches('/').to_string();
        }
    }
    abs_path.to_string()
}

/// Phase-04 namespace builder that prefixes a project-relative path with
/// the canonical package name when the importer file lies inside a
/// resolved [`crate::resolve::PackageEntry`].
///
/// Returns `"@scope/name::src/file.ts"` when the file is in a package
/// and `"src/file.ts"` (the same value `normalize_namespace` produces)
/// otherwise. Phase 04 ships this helper unused at the resolution
/// site, phase 10 will route [`FuncKey`] construction through it for
/// JS/TS files so cross-file callee lookup honours the package
/// boundary.
pub fn namespace_with_package(
    abs_path: &str,
    root: Option<&str>,
    module_graph: Option<&crate::resolve::ModuleGraph>,
) -> String {
    let plain = normalize_namespace(abs_path, root);
    let Some(graph) = module_graph else {
        return plain;
    };
    let path = std::path::Path::new(abs_path);
    match graph.package_for(path) {
        Some(pkg) => format!("{}::{}", pkg.name, plain),
        None => plain,
    }
}

/// Maximum bytes of `head_bytes` consulted by the shebang / content sniff.
/// Larger reads are tolerated — the helpers truncate internally.
const SNIFF_HEAD_LIMIT: usize = 200;

/// Parse a `#!` shebang line and map the interpreter name to a `Lang`.
///
/// Handles `/usr/bin/env <interp>` (with optional `-S` / `-i` flags),
/// direct `/usr/bin/<interp>`, and bare `<interp>` forms. Trailing version
/// digits (`python3`, `python3.11`) are stripped so the lookup matches the
/// base interpreter. Returns `None` for non-Nyx-supported interpreters
/// (`bash`, `sh`, `perl`, …).
fn lang_from_shebang(head: &[u8]) -> Option<Lang> {
    if !head.starts_with(b"#!") {
        return None;
    }
    let cap = head.len().min(SNIFF_HEAD_LIMIT);
    let line_end = head[..cap].iter().position(|&b| b == b'\n').unwrap_or(cap);
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let line = line.trim_end_matches('\r').trim();
    let rest = line.strip_prefix("#!")?.trim();

    let mut tokens = rest.split_whitespace();
    let first = tokens.next()?;
    let interpreter = if first.ends_with("/env") || first == "env" {
        // Skip env's own options (e.g. `-S`, `-i`, `--split-string`).
        tokens.find(|t| !t.starts_with('-'))?
    } else {
        first.rsplit('/').next()?
    };

    let base: String = interpreter
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    match base.as_str() {
        "python" => Some(Lang::Python),
        "node" | "nodejs" | "deno" | "bun" => Some(Lang::JavaScript),
        "ts" | "tsx" => Some(Lang::TypeScript),
        "ruby" => Some(Lang::Ruby),
        "php" => Some(Lang::Php),
        _ => None,
    }
}

/// Lightweight syntactic sniff over the first 200 bytes of a file.
///
/// Skips a leading shebang line (callers already tried it), then inspects up
/// to ~20 head lines for unambiguous language tokens. Returns `None` if
/// nothing convinces; the verifier's caller will record `LangUnsupported`
/// rather than misclassify.
fn sniff_content_lang(head: &[u8]) -> Option<Lang> {
    if head.is_empty() {
        return None;
    }
    let cap = head.len().min(SNIFF_HEAD_LIMIT);
    let text = std::str::from_utf8(&head[..cap]).ok()?;
    let body = match (text.starts_with("#!"), text.find('\n')) {
        (true, Some(i)) => &text[i + 1..],
        _ => text,
    };

    for raw in body.lines().take(20) {
        let line = raw.trim_start();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("<?php") {
            return Some(Lang::Php);
        }
        if line.starts_with("package main") {
            return Some(Lang::Go);
        }
        // Java `package foo.bar;` always ends with a semicolon.
        if line.starts_with("package ") && line.trim_end().ends_with(';') {
            return Some(Lang::Java);
        }
        if line.starts_with("import java.") || line.starts_with("public class ") {
            return Some(Lang::Java);
        }
        if line.starts_with("from __future__")
            || line.starts_with("from typing ")
            || (line.starts_with("def ") && line.contains(':'))
        {
            return Some(Lang::Python);
        }
        if line.starts_with("fn main") || line.starts_with("use std::") {
            return Some(Lang::Rust);
        }
        if line.starts_with("func ") && line.contains('(') {
            return Some(Lang::Go);
        }
        if line.starts_with("require ") || line.starts_with("require_relative ") {
            return Some(Lang::Ruby);
        }
        if line.starts_with("function ")
            || line.starts_with("const ")
            || line.starts_with("import {")
            || line.starts_with("export ")
        {
            return Some(Lang::JavaScript);
        }
    }
    None
}

#[cfg(test)]
mod tests;
