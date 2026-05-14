//! Project dependency capture + workdir staging (Phase 09 — Track D.1 + D.2).
//!
//! [`capture_project_dependencies`] reads the user's project root and
//! produces a [`CapturedDeps`] record describing every artifact the
//! harness will need at runtime — toolchain pin, direct imports of the
//! entry file, web framework signal, and local config files reachable
//! from the entry point.  [`stage_workdir`] then materialises a minimal
//! copy of those artifacts into the per-spec workdir so the sandboxed
//! harness can `import flask` (or its per-language equivalent) inside an
//! offline sandbox without leaking the whole project tree across the
//! filesystem boundary.
//!
//! The lang-specific manifest (`requirements.txt`, `package.json`,
//! `Cargo.toml`, …) is then synthesised by the per-language emitter via
//! [`crate::dynamic::lang::LangEmitter::materialize_runtime`] from the
//! [`Environment`] handed back by `stage_workdir`.
//!
//! ## Scope
//!
//! - Direct imports of the spec's entry file (tree-sitter walk, top-level
//!   `import` / `require` / `use` only — transitive imports are deferred
//!   to a future phase).
//! - Framework deps inferred from [`crate::utils::project::detect_frameworks`].
//! - Local config files reachable from the entry point's directory
//!   (`config.yaml`, `config.yml`, `.env`, `appsettings.json`, plus the
//!   toolchain-resolver-recognised manifest itself).
//! - Source files reached via reverse callgraph closure from the sink's
//!   enclosing function.  Bounded by [`MAX_WORKDIR_BYTES`] so a
//!   pathological closure does not copy the entire repository.
//!
//! The staged workdir is intentionally minimalist: every file copied has
//! to either be the entry, a dep manifest, a config file, or an in-closure
//! source file.  The 10 MiB ceiling protects against runaway full-tree
//! copy regressions called out in the Phase 09 acceptance.

use crate::callgraph::{callers_of, CallGraph};
use crate::dynamic::spec::HarnessSpec;
use crate::dynamic::toolchain::{self, ToolchainResolution};
use crate::summary::GlobalSummaries;
use crate::symbol::{FuncKey, Lang};
use crate::utils::project::{detect_frameworks, DetectedFramework};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

// ── Phase 11 — Track D.4: deterministic secret derivation ────────────────────

/// Prefix prepended to every derived secret so a leaked harness value is
/// immediately recognisable as a Nyx stub rather than a real credential.
pub const SECRET_VALUE_PREFIX: &str = "nyx-stub-";

/// Deterministic placeholder for a secret env var.
///
/// Constructed by [`derive_secret`] from `BLAKE3(spec_hash || env_var_name)`
/// and prefixed with [`SECRET_VALUE_PREFIX`].  The value is stable for the
/// lifetime of a spec, so two harness invocations under the same
/// [`HarnessSpec`] see identical credentials — but never the user's real
/// secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    /// Raw value, ready to drop into `env`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Derive a deterministic placeholder for `env_var_name` keyed by
/// `spec_hash`.
///
/// `BLAKE3(spec_hash || '|' || env_var_name)` → first 32 hex chars →
/// `"nyx-stub-{hex}"`.  The separator (`|`) prevents accidental collisions
/// between `("abc", "DEF")` and `("abcDEF", "")`.
///
/// Length is bounded at 32 hex characters (128 bits) so the value remains
/// short enough to fit comfortably in URLs, JSON config blobs, and POSIX
/// argv without inflating the env footprint.
pub fn derive_secret(spec_hash: &str, env_var_name: &str) -> SecretValue {
    let mut hasher = blake3::Hasher::new();
    hasher.update(spec_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(env_var_name.as_bytes());
    let hex = hasher.finalize().to_hex();
    let mut out = String::with_capacity(SECRET_VALUE_PREFIX.len() + 32);
    out.push_str(SECRET_VALUE_PREFIX);
    out.push_str(&hex.as_str()[..32]);
    SecretValue(out)
}

/// Scan `entry_file` for env-var references in `lang`.
///
/// Returns the set of env-var names referenced via the language's standard
/// env access API:
///
/// | Lang | Patterns |
/// |---|---|
/// | Python | `os.environ.get("X")`, `os.environ["X"]`, `os.getenv("X")` |
/// | JS/TS  | `process.env.X`, `process.env["X"]` |
/// | Java   | `System.getenv("X")` |
/// | Rust   | `std::env::var("X")`, `env::var("X")` |
/// | Go     | `os.Getenv("X")`, `os.LookupEnv("X")` |
/// | PHP    | `getenv("X")`, `$_ENV["X"]`, `$_SERVER["X"]` |
/// | Ruby   | `ENV["X"]`, `ENV.fetch("X")` |
/// | C/C++  | `getenv("X")` |
///
/// Static substring scan — bounded by [`IMPORT_SCAN_LIMIT`] like the import
/// extractor.  No AST: an entry-file with `os.environ.get(some_var)` (a
/// non-literal arg) is intentionally skipped; the secret bag is populated
/// from literal references only so a typo cannot produce noisy injection.
pub fn extract_env_var_references(entry_file: &Path, lang: Lang) -> Vec<String> {
    let bytes = match read_bounded(entry_file) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let source = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let patterns: &[&str] = match lang {
        Lang::Python => &[
            "os.environ.get(",
            "os.environ[",
            "os.getenv(",
            "environ.get(",
            "environ[",
            "getenv(",
        ],
        Lang::JavaScript | Lang::TypeScript => &["process.env.", "process.env["],
        Lang::Java => &["System.getenv(", "getenv("],
        Lang::Rust => &["std::env::var(", "env::var(", "env::var_os(", "std::env::var_os("],
        Lang::Go => &["os.Getenv(", "os.LookupEnv("],
        Lang::Php => &["getenv(", "$_ENV[", "$_SERVER["],
        Lang::Ruby => &["ENV[", "ENV.fetch(", "ENV.fetch "],
        Lang::C | Lang::Cpp => &["getenv("],
    };

    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for pat in patterns {
        let mut start = 0;
        while let Some(rel) = source[start..].find(pat) {
            let abs = start + rel + pat.len();
            start = abs;
            let tail = &source[abs..];
            let name = match lang {
                Lang::JavaScript | Lang::TypeScript if *pat == "process.env." => {
                    extract_identifier_name(tail)
                }
                _ => extract_quoted_arg(tail),
            };
            if let Some(name) = name {
                if !name.is_empty() && is_env_var_name(&name) && seen.insert(name.clone()) {
                    out.push(name);
                }
            }
        }
    }
    out
}

/// Extract a quoted (single or double quote) literal argument starting at
/// `s`.  Skips leading whitespace; stops at the matching close-quote.
/// Returns `None` when the first non-whitespace char is not a quote — the
/// arg is dynamic and the scanner deliberately skips it.
fn extract_quoted_arg(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = match bytes[i] {
        b'"' => b'"',
        b'\'' => b'\'',
        b'`' => b'`',
        _ => return None,
    };
    i += 1;
    let start = i;
    while i < bytes.len() && bytes[i] != quote {
        if bytes[i] == b'\n' {
            return None;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    std::str::from_utf8(&bytes[start..i]).ok().map(|s| s.to_owned())
}

/// Extract a bare identifier (e.g. `FOO` in `process.env.FOO`).  Stops at
/// the first non-identifier byte.
fn extract_identifier_name(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let is_ident = c.is_ascii_alphanumeric() || c == b'_';
        if !is_ident {
            break;
        }
        i += 1;
    }
    if i == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..i]).ok().map(|s| s.to_owned())
}

/// Permissive env-var-name shape: starts with a letter or underscore, then
/// any of `[A-Za-z0-9_]`.  Filters out blatantly bogus parses (e.g. when
/// the quoted scanner picks up `{`).
fn is_env_var_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Build the per-spec secret bag: each env var the entry file references
/// gets a deterministic `(name, derive_secret(spec_hash, name))` entry.
///
/// Returned in deterministic source-order so two runs against the same
/// inputs produce byte-identical env layouts.
pub fn build_secret_bag(
    entry_file: &Path,
    lang: Lang,
    spec_hash: &str,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for name in extract_env_var_references(entry_file, lang) {
        let val = derive_secret(spec_hash, &name);
        out.push((name, val.into_string()));
    }
    out
}

/// Hard upper bound on the bytes a staged workdir may consume after
/// `stage_workdir` returns. Phase 09 acceptance pins this to 10 MiB so a
/// pathological full-tree copy regression is caught at the test boundary
/// rather than ballooning the sandbox into the user's whole repo.
pub const MAX_WORKDIR_BYTES: u64 = 10 * 1024 * 1024;

/// Bytes scanned for `import` / `require` / `use` statements when the
/// per-language extractor is asked to enumerate the entry file's direct
/// dependencies.  64 KiB covers every reasonable header / preamble; we
/// intentionally do not walk the whole file because the import shape
/// almost always lives at the top.
const IMPORT_SCAN_LIMIT: usize = 64 * 1024;

/// Names of common config files reachable from the entry point. The
/// existence test is `entry_dir.join(name).is_file()` so we never recurse
/// into subdirectories — that's intentional: the harness boots from
/// `workdir/` and any path beneath the entry's directory is reachable via
/// relative paths only if it sits at the same level.
const CONFIG_FILE_CANDIDATES: &[&str] = &[
    "config.yaml",
    "config.yml",
    ".env",
    "appsettings.json",
    "settings.json",
    "config.toml",
    "config.json",
];

/// Per-language manifest files (lockfile + manifest pair) recognised by
/// the toolchain resolver.  When present at `project_root`, these are
/// copied verbatim into the staged workdir so the build sandbox sees the
/// user's pinned dependency set.  Order is significant only insofar as
/// the first match wins for [`CapturedDeps::lockfile_origin`].
const MANIFEST_FILES_BY_LANG: &[(Lang, &[&str])] = &[
    (Lang::Python, &["requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock"]),
    (Lang::JavaScript, &["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]),
    (Lang::TypeScript, &["package.json", "package-lock.json", "yarn.lock", "tsconfig.json"]),
    (Lang::Rust, &["Cargo.toml", "Cargo.lock"]),
    (Lang::Go, &["go.mod", "go.sum"]),
    (Lang::Java, &["pom.xml", "build.gradle", "build.gradle.kts"]),
    (Lang::Php, &["composer.json", "composer.lock"]),
    (Lang::Ruby, &["Gemfile", "Gemfile.lock"]),
    (Lang::C, &["Makefile", "CMakeLists.txt"]),
    (Lang::Cpp, &["Makefile", "CMakeLists.txt"]),
];

/// Static-analysis output captured from the project, ready to be staged
/// into the harness workdir.
///
/// Returned by [`capture_project_dependencies`] and consumed by
/// [`stage_workdir`].  The struct deliberately separates *capture* (read
/// the project tree, no writes) from *staging* (write the workdir, no
/// reads of the source tree), so a future phase can persist
/// `CapturedDeps` to disk and re-stage without re-walking the source.
#[derive(Debug, Clone)]
pub struct CapturedDeps {
    /// Absolute path to the user's project root used as the read anchor.
    pub project_root: PathBuf,
    /// Absolute path to the entry file (resolved against `project_root`).
    pub entry_file: PathBuf,
    /// Resolved language toolchain pin (version + drift flag).
    pub toolchain: ToolchainResolution,
    /// Top-level imports literally appearing in [`Self::entry_file`].
    ///
    /// `lib_name` is the canonical package/module the import names.  The
    /// per-language `materialize_runtime` impl pins each entry to the
    /// project's framework version when possible, or to a known-good
    /// recent version otherwise.
    pub direct_deps: Vec<String>,
    /// Web frameworks detected from project manifests.  Surfaced as a
    /// separate field (rather than folded into `direct_deps`) so the
    /// emitters can decide whether to pin to a specific framework
    /// version even when the entry file imports the framework
    /// transitively.
    pub frameworks: Vec<DetectedFramework>,
    /// Three-valued lang-has-framework signal (see
    /// [`FrameworkContext::lang_has_web_framework`]).
    pub framework_signal: Option<bool>,
    /// Absolute paths of local config files reachable from the entry
    /// point's directory.  Each is copied verbatim into the workdir
    /// during [`stage_workdir`].
    pub config_files: Vec<PathBuf>,
    /// Source files reachable from the sink's enclosing function via
    /// reverse callgraph edges.  Always includes the entry file.  Empty
    /// when no summaries / callgraph are threaded into the capture step.
    pub source_closure: Vec<PathBuf>,
    /// Manifest files (lockfile + project manifest pair) recognised for
    /// [`Self::toolchain`]'s language.  Each entry is an absolute path
    /// inside `project_root`; the first existing entry from
    /// [`MANIFEST_FILES_BY_LANG`] wins for [`Self::lockfile`].
    pub manifests: Vec<PathBuf>,
    /// First recognised manifest file (== `manifests[0]` when present).
    /// Used by the per-language emitter as the canonical lockfile when
    /// synthesising the staged manifest.
    pub lockfile: Option<PathBuf>,
}

/// Runtime environment handle owned by the staging step.
///
/// Holds everything the per-language `materialize_runtime` impl needs to
/// emit a pinned manifest, plus the workdir handle so the staged paths
/// resolve correctly.  Construction is owned by [`stage_workdir`]; the
/// fields are otherwise read-only so future stub injection (Phase 09+
/// extensions) can extend the struct without invalidating existing
/// callers.
#[derive(Debug, Clone)]
pub struct Environment {
    /// Stable hash of the originating spec.  Copied here so the emitter
    /// can include it in the manifest comment header for forensic
    /// traceability.
    pub spec_hash: String,
    /// Absolute path to the workdir that was just staged.
    pub workdir: PathBuf,
    /// Absolute path to the canonical lockfile staged into the workdir
    /// (e.g. `workdir/requirements.txt`, `workdir/Cargo.lock`).  `None`
    /// when the language has no recognised lockfile or the user's
    /// project carried none.
    pub lockfile: Option<PathBuf>,
    /// Source files materialised into the workdir, as paths *relative*
    /// to the workdir root (e.g. `"src/handler.py"`).
    pub staged_sources: Vec<PathBuf>,
    /// Environment variables the harness should set before invoking the
    /// entry point.  Populated by [`build_secret_bag`] during
    /// [`stage_workdir_full`] (Phase 11 — Track D.4) with deterministic
    /// stub values for every env var the entry file literally
    /// references.  Phase 10 stub endpoints (SQL DB path, HTTP origin
    /// URL, etc.) are layered on top by the verifier via
    /// [`crate::dynamic::sandbox::SandboxOptions::extra_env`].
    pub env_vars: Vec<(String, String)>,
    /// Stub registry handles.  Reserved for the Phase 10 stub-injection
    /// layer; Phase 09 stages no stubs so this is always empty.
    pub stub_handles: Vec<String>,
    /// Language-toolchain pin carried over from
    /// [`CapturedDeps::toolchain`] so the emitter does not need both
    /// inputs.
    pub toolchain: ToolchainResolution,
    /// Direct deps the entry imports.  Same shape as
    /// [`CapturedDeps::direct_deps`].
    pub direct_deps: Vec<String>,
    /// Frameworks detected in the project root.
    pub frameworks: Vec<DetectedFramework>,
    /// Language pinned via the originating spec.  Cached here so the
    /// emitter does not have to re-thread the spec.
    pub lang: Lang,
}

/// Manifest / lockfile artifacts the harness build needs alongside the
/// generated source.  Returned by
/// [`crate::dynamic::lang::LangEmitter::materialize_runtime`].
///
/// Mirrors [`crate::dynamic::lang::HarnessSource::extra_files`] so the
/// harness staging path can write the manifest directly via the existing
/// extra-files loop.
#[derive(Debug, Clone, Default)]
pub struct RuntimeArtifacts {
    /// `(relative_path, contents)` pairs written under `Environment::workdir`.
    pub files: Vec<(String, String)>,
}

impl RuntimeArtifacts {
    /// Convenience builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a `(rel_path, content)` artifact.
    pub fn push(&mut self, rel_path: impl Into<String>, content: impl Into<String>) {
        self.files.push((rel_path.into(), content.into()));
    }
}

/// Walk the user's project tree to assemble the runtime dependencies the
/// harness needs.
///
/// Reads only — never writes.  The returned [`CapturedDeps`] is the
/// single input to [`stage_workdir`], which is the sole owner of the
/// workdir filesystem mutations.
///
/// Always returns a populated record: missing inputs are best-effort and
/// fall back to defaults (system toolchain, empty deps).  The function
/// never fails — every failure mode (manifest unreadable, entry file
/// missing) is folded into the returned record.
pub fn capture_project_dependencies(project_root: &Path, spec: &HarnessSpec) -> CapturedDeps {
    capture_project_dependencies_with_context(project_root, spec, None, None)
}

/// Strategy-aware [`capture_project_dependencies`] that consults the
/// whole-program [`CallGraph`] and [`GlobalSummaries`] when present.
///
/// When both are provided, [`CapturedDeps::source_closure`] is populated
/// via reverse-edge BFS from the sink's enclosing function so the
/// staging step copies every file the entry transitively depends on.
/// When either is `None` the closure shrinks to a single-file set
/// containing only the entry — staging still works for the simple case
/// but cross-file helpers are not copied across.
pub fn capture_project_dependencies_with_context(
    project_root: &Path,
    spec: &HarnessSpec,
    summaries: Option<&GlobalSummaries>,
    callgraph: Option<&CallGraph>,
) -> CapturedDeps {
    let entry_file = resolve_under_root(project_root, &spec.entry_file);

    let toolchain = resolve_toolchain_for_lang(spec.lang, project_root);

    let direct_deps = extract_direct_deps(&entry_file, spec.lang);

    let framework_ctx = detect_frameworks(project_root);
    let frameworks = framework_ctx.frameworks.clone();
    let framework_signal = framework_ctx.lang_has_web_framework(framework_slug_for_lang(spec.lang));

    let config_files = collect_config_files(&entry_file, project_root);

    let manifests = collect_manifest_files(spec.lang, project_root);
    let lockfile = manifests.first().cloned();

    let source_closure = compute_source_closure(&entry_file, project_root, spec, summaries, callgraph);

    CapturedDeps {
        project_root: project_root.to_path_buf(),
        entry_file,
        toolchain,
        direct_deps,
        frameworks,
        framework_signal,
        config_files,
        source_closure,
        manifests,
        lockfile,
    }
}

/// Materialise a minimal copy of the project into `workdir`.
///
/// Writes (in order):
/// 1. The entry file itself (under its source-tree-relative path so
///    relative `from .x import y` works inside the workdir).
/// 2. Every file in `captured.source_closure`, preserving the
///    `project_root`-relative layout.
/// 3. Every manifest file in `captured.manifests`.
/// 4. Every local config file in `captured.config_files`.
///
/// Each write checks the running workdir size against
/// [`MAX_WORKDIR_BYTES`] and stops early on overflow; the function
/// returns `io::ErrorKind::FileTooLarge` in that case so the caller can
/// surface a `Inconclusive(WorkdirOverflow)` verdict in a future phase.
///
/// The returned [`Environment`] is the sole handle subsequent emitters
/// consult; callers must not assume the workdir is otherwise mutated
/// outside of this function (the harness builder still writes the
/// generated source via [`crate::dynamic::harness::build`]).
pub fn stage_workdir(captured: &CapturedDeps, workdir: &Path) -> io::Result<Environment> {
    let lang = guess_lang_for_toolchain(&captured.toolchain.toolchain_id);
    stage_workdir_full(captured, workdir, "", lang)
}

/// Like [`stage_workdir`] but lets the caller thread the originating
/// spec hash into the resulting [`Environment`].
pub fn stage_workdir_with_spec_hash(
    captured: &CapturedDeps,
    workdir: &Path,
    spec_hash: &str,
) -> io::Result<Environment> {
    let lang = guess_lang_for_toolchain(&captured.toolchain.toolchain_id);
    stage_workdir_full(captured, workdir, spec_hash, lang)
}

/// Strategy-aware [`stage_workdir`] that lets the caller pin the
/// [`Environment`]'s [`Lang`] explicitly (rather than guessing from the
/// toolchain id).  Used by the integration tests and by future harness
/// staging plumbing that already has a [`HarnessSpec`] in scope.
pub fn stage_workdir_full(
    captured: &CapturedDeps,
    workdir: &Path,
    spec_hash: &str,
    lang: Lang,
) -> io::Result<Environment> {
    std::fs::create_dir_all(workdir)?;

    let mut running_bytes: u64 = 0;
    let mut staged_sources: Vec<PathBuf> = Vec::new();

    // 1. Entry file — preserve project-relative layout when the entry
    //    lives under project_root, otherwise fall back to the basename.
    if captured.entry_file.exists() {
        let rel = rel_under_root(&captured.entry_file, &captured.project_root)
            .unwrap_or_else(|| PathBuf::from(captured.entry_file.file_name().unwrap_or_default()));
        running_bytes = copy_into_workdir(
            &captured.entry_file,
            workdir,
            &rel,
            running_bytes,
            &mut staged_sources,
        )?;
    }

    // 2. Source closure — every reachable in-closure file.
    for src in &captured.source_closure {
        if src == &captured.entry_file {
            continue;
        }
        if !src.exists() {
            continue;
        }
        let rel = match rel_under_root(src, &captured.project_root) {
            Some(r) => r,
            None => continue,
        };
        running_bytes = copy_into_workdir(src, workdir, &rel, running_bytes, &mut staged_sources)?;
    }

    // 3. Manifests (project-relative).
    let mut lockfile_in_workdir: Option<PathBuf> = None;
    for manifest in &captured.manifests {
        if !manifest.exists() {
            continue;
        }
        let rel = match rel_under_root(manifest, &captured.project_root) {
            Some(r) => r,
            None => continue,
        };
        running_bytes = copy_into_workdir(
            manifest,
            workdir,
            &rel,
            running_bytes,
            &mut staged_sources,
        )?;
        if lockfile_in_workdir.is_none() {
            lockfile_in_workdir = Some(workdir.join(&rel));
        }
    }

    // 4. Config files (preserve relative layout under project_root).
    for cfg in &captured.config_files {
        if !cfg.exists() {
            continue;
        }
        let rel = match rel_under_root(cfg, &captured.project_root) {
            Some(r) => r,
            None => PathBuf::from(cfg.file_name().unwrap_or_default()),
        };
        running_bytes =
            copy_into_workdir(cfg, workdir, &rel, running_bytes, &mut staged_sources)?;
    }

    // Phase 11 — Track D.4: populate the per-spec secret bag for every
    // env var the entry file literally references.  `spec_hash` is empty
    // for the legacy [`stage_workdir`] entry point; in that case the
    // derived values still hash deterministically (collisions are avoided
    // by the env-var name component) but two distinct specs would alias.
    // Callers with a real spec hash should use
    // [`stage_workdir_full`] / [`stage_workdir_with_spec_hash`].
    let env_vars = build_secret_bag(&captured.entry_file, lang, spec_hash);

    Ok(Environment {
        spec_hash: spec_hash.to_owned(),
        workdir: workdir.to_path_buf(),
        lockfile: lockfile_in_workdir,
        staged_sources,
        env_vars,
        stub_handles: Vec::new(),
        toolchain: captured.toolchain.clone(),
        direct_deps: captured.direct_deps.clone(),
        frameworks: captured.frameworks.clone(),
        lang,
    })
}

fn guess_lang_for_toolchain(toolchain_id: &str) -> Lang {
    Lang::from_slug(framework_slug_for_lang_for_toolchain(toolchain_id)).unwrap_or(Lang::Python)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn copy_into_workdir(
    src: &Path,
    workdir: &Path,
    rel: &Path,
    running_bytes: u64,
    staged: &mut Vec<PathBuf>,
) -> io::Result<u64> {
    let metadata = match std::fs::metadata(src) {
        Ok(m) => m,
        Err(_) => return Ok(running_bytes),
    };
    let size = metadata.len();
    if running_bytes.saturating_add(size) > MAX_WORKDIR_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "staged workdir would exceed {} bytes (next file `{}` = {} bytes)",
                MAX_WORKDIR_BYTES,
                rel.display(),
                size
            ),
        ));
    }
    let dest = workdir.join(rel);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, &dest)?;
    staged.push(rel.to_path_buf());
    Ok(running_bytes.saturating_add(size))
}

fn resolve_under_root(project_root: &Path, entry_file: &str) -> PathBuf {
    let p = Path::new(entry_file);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    project_root.join(p)
}

fn rel_under_root(path: &Path, root: &Path) -> Option<PathBuf> {
    let abs_path = path.canonicalize().ok().unwrap_or_else(|| path.to_path_buf());
    let abs_root = root.canonicalize().ok().unwrap_or_else(|| root.to_path_buf());
    abs_path
        .strip_prefix(&abs_root)
        .ok()
        .map(|p| p.to_path_buf())
}

fn resolve_toolchain_for_lang(lang: Lang, project_root: &Path) -> ToolchainResolution {
    match lang {
        Lang::Python => toolchain::resolve_python(project_root),
        Lang::Rust => toolchain::resolve_rust(project_root),
        Lang::JavaScript | Lang::TypeScript => toolchain::resolve_node(project_root),
        Lang::Go => toolchain::resolve_go(project_root),
        Lang::Java => toolchain::resolve_java(project_root),
        Lang::Php => toolchain::resolve_php(project_root),
        _ => toolchain::resolve_python(project_root),
    }
}

fn framework_slug_for_lang(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => "python",
        Lang::JavaScript => "javascript",
        Lang::TypeScript => "typescript",
        Lang::Java => "java",
        Lang::Go => "go",
        Lang::Php => "php",
        Lang::Ruby => "ruby",
        Lang::Rust => "rust",
        Lang::C => "c",
        Lang::Cpp => "cpp",
    }
}

fn framework_slug_for_lang_for_toolchain(toolchain_id: &str) -> &'static str {
    if toolchain_id.starts_with("python") {
        "python"
    } else if toolchain_id.starts_with("node") {
        "javascript"
    } else if toolchain_id.starts_with("rust") {
        "rust"
    } else if toolchain_id.starts_with("go") {
        "go"
    } else if toolchain_id.starts_with("java") {
        "java"
    } else if toolchain_id.starts_with("php") {
        "php"
    } else {
        "python"
    }
}

fn collect_config_files(entry_file: &Path, project_root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let dirs: Vec<PathBuf> = {
        let mut v = Vec::new();
        v.push(project_root.to_path_buf());
        if let Some(parent) = entry_file.parent() {
            if parent != project_root && parent.starts_with(project_root) {
                v.push(parent.to_path_buf());
            }
        }
        v
    };
    for dir in &dirs {
        for name in CONFIG_FILE_CANDIDATES {
            let cand = dir.join(name);
            if cand.is_file() && !seen.contains(&cand) {
                seen.insert(cand.clone());
                out.push(cand);
            }
        }
    }
    out
}

fn collect_manifest_files(lang: Lang, project_root: &Path) -> Vec<PathBuf> {
    let names = MANIFEST_FILES_BY_LANG
        .iter()
        .find(|(l, _)| *l == lang)
        .map(|(_, n)| *n)
        .unwrap_or(&[]);
    let mut out: Vec<PathBuf> = Vec::new();
    for name in names {
        let cand = project_root.join(name);
        if cand.is_file() {
            out.push(cand);
        }
    }
    out
}

/// Walk `entry_file` for top-level imports and project-internal package
/// names.  Distinct per language; the fall-through returns an empty Vec
/// so unsupported languages do not crash, they just stage with no
/// imports.
pub(crate) fn extract_direct_deps(entry_file: &Path, lang: Lang) -> Vec<String> {
    let bytes = match read_bounded(entry_file) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let head = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    match lang {
        Lang::Python => extract_python_imports(head),
        Lang::JavaScript | Lang::TypeScript => extract_js_imports(head),
        Lang::Ruby => extract_ruby_imports(head),
        Lang::Php => extract_php_imports(head),
        Lang::Go => extract_go_imports(head),
        Lang::Java => extract_java_imports(head),
        Lang::Rust => extract_rust_imports(head),
        Lang::C | Lang::Cpp => extract_c_includes(head),
    }
}

fn extract_python_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in source.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let candidate = if let Some(rest) = line.strip_prefix("from ") {
            // `from X.Y import Z`  → top-level pkg = "X"
            let mod_name = rest.split_whitespace().next().unwrap_or("");
            if mod_name.is_empty() || mod_name.starts_with('.') {
                continue;
            }
            mod_name.split('.').next().unwrap_or("").to_owned()
        } else if let Some(rest) = line.strip_prefix("import ") {
            // `import X.Y`        → top-level pkg = "X"
            // `import X.Y as Z`   → top-level pkg = "X"
            // `import X, Y`       → first "X" only (best-effort)
            let mod_name = rest.split([',', ' ']).next().unwrap_or("").trim();
            if mod_name.is_empty() {
                continue;
            }
            mod_name.split('.').next().unwrap_or("").to_owned()
        } else {
            continue;
        };
        if candidate.is_empty() {
            continue;
        }
        if !seen.contains(&candidate) {
            seen.insert(candidate.clone());
            out.push(candidate);
        }
    }
    out
}

fn extract_js_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push = |s: &str, out: &mut Vec<String>, seen: &mut HashSet<String>| {
        let trimmed = s.trim_matches(|c: char| c == '\'' || c == '"' || c == '`');
        if trimmed.is_empty() || trimmed.starts_with('.') || trimmed.starts_with('/') {
            return;
        }
        // Scoped pkg (`@scope/name`) keeps full prefix; bare pkg keeps top segment.
        let canonical = if trimmed.starts_with('@') {
            let parts: Vec<&str> = trimmed.splitn(3, '/').collect();
            if parts.len() >= 2 {
                format!("{}/{}", parts[0], parts[1])
            } else {
                trimmed.to_owned()
            }
        } else {
            trimmed.split('/').next().unwrap_or(trimmed).to_owned()
        };
        if !seen.contains(&canonical) {
            seen.insert(canonical.clone());
            out.push(canonical);
        }
    };
    for line in source.lines() {
        let line = line.trim_start();
        if let Some(idx) = line.find("from ") {
            // `import x from 'pkg'`
            let after = &line[idx + 5..];
            let after = after.trim_start();
            if let Some(end) = after.find(['\'', '"', '`']) {
                let quote = after.as_bytes()[end] as char;
                if let Some(close) = after[end + 1..].find(quote) {
                    push(&after[end + 1..end + 1 + close], &mut out, &mut seen);
                }
            }
        }
        if let Some(idx) = line.find("require(") {
            let after = &line[idx + 8..];
            let after = after.trim_start();
            if let Some(end) = after.find(['\'', '"', '`']) {
                let quote = after.as_bytes()[end] as char;
                if let Some(close) = after[end + 1..].find(quote) {
                    push(&after[end + 1..end + 1 + close], &mut out, &mut seen);
                }
            }
        }
        if line.starts_with("import ") && !line.contains("from ") {
            // Side-effect import: `import 'pkg'`.
            let rest = line.trim_start_matches("import ").trim();
            push(rest, &mut out, &mut seen);
        }
    }
    out
}

fn extract_ruby_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in source.lines() {
        let line = line.trim_start();
        let rest = if let Some(r) = line.strip_prefix("require_relative ") {
            r
        } else if let Some(r) = line.strip_prefix("require ") {
            r
        } else {
            continue;
        };
        let trimmed = rest.trim().trim_matches(|c: char| c == '\'' || c == '"');
        if trimmed.is_empty() {
            continue;
        }
        let pkg = trimmed.split('/').next().unwrap_or(trimmed).to_owned();
        if !seen.contains(&pkg) {
            seen.insert(pkg.clone());
            out.push(pkg);
        }
    }
    out
}

fn extract_php_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in source.lines() {
        let line = line.trim_start();
        let rest = if let Some(r) = line.strip_prefix("use ") {
            r
        } else if let Some(r) = line.strip_prefix("require_once ") {
            r
        } else if let Some(r) = line.strip_prefix("require ") {
            r
        } else if let Some(r) = line.strip_prefix("include ") {
            r
        } else {
            continue;
        };
        let trimmed = rest
            .trim()
            .trim_end_matches(';')
            .trim_matches(|c: char| c == '\'' || c == '"');
        if trimmed.is_empty() {
            continue;
        }
        let pkg = trimmed.split('\\').next().unwrap_or(trimmed).to_owned();
        if !seen.contains(&pkg) {
            seen.insert(pkg.clone());
            out.push(pkg);
        }
    }
    out
}

fn extract_go_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut in_block = false;
    for line in source.lines() {
        let line = line.trim_start();
        if line.starts_with("import (") {
            in_block = true;
            continue;
        }
        if in_block {
            if line.starts_with(')') {
                in_block = false;
                continue;
            }
            let trimmed = line.trim().trim_matches(|c: char| c == '\'' || c == '"');
            if trimmed.is_empty() {
                continue;
            }
            // Skip aliased imports' alias prefix: `foo "pkg"`.
            let pkg_part = trimmed
                .rsplit_once(' ')
                .map(|(_, r)| r.trim_matches(|c: char| c == '"' || c == '`' || c == '\''))
                .unwrap_or(trimmed)
                .trim_matches(|c: char| c == '"' || c == '`' || c == '\'');
            if pkg_part.is_empty() || pkg_part.starts_with("//") {
                continue;
            }
            if !seen.contains(pkg_part) {
                seen.insert(pkg_part.to_owned());
                out.push(pkg_part.to_owned());
            }
        } else if let Some(rest) = line.strip_prefix("import ") {
            let trimmed = rest.trim().trim_matches(|c: char| c == '"' || c == '`');
            if !trimmed.is_empty() && !seen.contains(trimmed) {
                seen.insert(trimmed.to_owned());
                out.push(trimmed.to_owned());
            }
        }
    }
    out
}

fn extract_java_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in source.lines() {
        let line = line.trim_start();
        let rest = match line.strip_prefix("import ") {
            Some(r) => r,
            None => continue,
        };
        let trimmed = rest.trim().trim_end_matches(';');
        if trimmed.is_empty() {
            continue;
        }
        // Top-level Java package = first dotted segment.
        let pkg = trimmed.split('.').next().unwrap_or(trimmed).to_owned();
        if !seen.contains(&pkg) {
            seen.insert(pkg.clone());
            out.push(pkg);
        }
    }
    out
}

fn extract_rust_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in source.lines() {
        let line = line.trim_start();
        let rest = match line.strip_prefix("use ") {
            Some(r) => r,
            None => match line.strip_prefix("extern crate ") {
                Some(r) => r,
                None => continue,
            },
        };
        let trimmed = rest.trim().trim_end_matches(';');
        if trimmed.is_empty() {
            continue;
        }
        let crate_name = trimmed
            .split("::")
            .next()
            .unwrap_or(trimmed)
            .split([' ', ','])
            .next()
            .unwrap_or(trimmed)
            .to_owned();
        if crate_name == "self" || crate_name == "super" || crate_name == "crate" {
            continue;
        }
        if !seen.contains(&crate_name) {
            seen.insert(crate_name.clone());
            out.push(crate_name);
        }
    }
    out
}

fn extract_c_includes(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in source.lines() {
        let line = line.trim_start();
        if !line.starts_with("#include") {
            continue;
        }
        let rest = line.trim_start_matches("#include").trim();
        let trimmed = rest
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim_start_matches('"')
            .trim_end_matches('"');
        if trimmed.is_empty() {
            continue;
        }
        if !seen.contains(trimmed) {
            seen.insert(trimmed.to_owned());
            out.push(trimmed.to_owned());
        }
    }
    out
}

fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut buf: Vec<u8> = Vec::new();
    let mut reader = std::io::BufReader::new(file).take(IMPORT_SCAN_LIMIT as u64);
    reader.read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Reverse-edge callgraph closure starting from the spec's sink-enclosing
/// function and walking outward through callers until the entry file is
/// reached or there are no more callers.  Falls back to the entry-file
/// only when summaries / callgraph are not present.
///
/// The resulting set is bounded by the number of [`FuncKey`]s in the
/// call graph; in practice harness fixtures sit at <100 nodes so the BFS
/// terminates almost immediately.
fn compute_source_closure(
    entry_file: &Path,
    project_root: &Path,
    spec: &HarnessSpec,
    summaries: Option<&GlobalSummaries>,
    callgraph: Option<&CallGraph>,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    let push = |p: PathBuf, out: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>| {
        if !seen.contains(&p) {
            seen.insert(p.clone());
            out.push(p);
        }
    };

    push(entry_file.to_path_buf(), &mut out, &mut seen);

    let (Some(gs), Some(cg)) = (summaries, callgraph) else {
        return out;
    };

    let sink_file_abs = resolve_under_root(project_root, &spec.sink_file);

    // Seed: every FuncKey whose namespace is the sink file.
    let mut frontier: Vec<FuncKey> = gs
        .iter()
        .filter_map(|(k, _)| {
            let ns_abs = resolve_under_root(project_root, &k.namespace);
            if paths_equal(&ns_abs, &sink_file_abs) {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();

    let mut visited: HashSet<FuncKey> = frontier.iter().cloned().collect();
    let mut steps = 0;
    const MAX_STEPS: usize = 256;
    while let Some(callee) = frontier.pop() {
        if steps > MAX_STEPS {
            break;
        }
        steps += 1;
        let ns_abs = resolve_under_root(project_root, &callee.namespace);
        push(ns_abs.clone(), &mut out, &mut seen);
        for caller in callers_of(cg, &callee) {
            if visited.contains(&caller) {
                continue;
            }
            visited.insert(caller.clone());
            frontier.push(caller);
        }
    }
    out
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    let a_can = a.canonicalize().ok();
    let b_can = b.canonicalize().ok();
    match (a_can, b_can) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy};
    use crate::labels::Cap;
    use std::fs;
    use tempfile::TempDir;

    fn fake_spec(entry_file: &str, lang: Lang) -> HarnessSpec {
        HarnessSpec {
            finding_id: "0000000000000001".into(),
            entry_file: entry_file.into(),
            entry_name: "handler".into(),
            entry_kind: EntryKind::Function,
            lang,
            toolchain_id: "python-3.11".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: entry_file.into(),
            sink_line: 10,
            spec_hash: "test0000abcd1234".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
        }
    }

    #[test]
    fn extract_python_imports_picks_top_level_pkg() {
        let src = r#"
from flask import Flask, request
import os
import sqlalchemy
import pandas as pd
from sqlalchemy.orm import sessionmaker
"#;
        let deps = extract_python_imports(src);
        assert!(deps.contains(&"flask".to_owned()));
        assert!(deps.contains(&"os".to_owned()));
        assert!(deps.contains(&"sqlalchemy".to_owned()));
        assert!(deps.contains(&"pandas".to_owned()));
        // sqlalchemy.orm is deduped to "sqlalchemy".
        assert_eq!(deps.iter().filter(|d| *d == "sqlalchemy").count(), 1);
    }

    #[test]
    fn extract_js_imports_handles_scoped_pkg() {
        let src = r#"
import express from 'express';
const helmet = require("helmet");
import { Router } from '@koa/router';
import './local-thing';
"#;
        let deps = extract_js_imports(src);
        assert!(deps.contains(&"express".to_owned()));
        assert!(deps.contains(&"helmet".to_owned()));
        assert!(deps.contains(&"@koa/router".to_owned()));
        // Relative imports are skipped.
        assert!(!deps.iter().any(|d| d.starts_with('.')));
    }

    #[test]
    fn extract_rust_imports_collects_crates() {
        let src = "use serde::Deserialize;\nuse tokio::net::TcpListener;\nextern crate libc;\nuse crate::foo::bar;\n";
        let deps = extract_rust_imports(src);
        assert!(deps.contains(&"serde".to_owned()));
        assert!(deps.contains(&"tokio".to_owned()));
        assert!(deps.contains(&"libc".to_owned()));
        // Project-internal references skipped.
        assert!(!deps.contains(&"crate".to_owned()));
    }

    #[test]
    fn extract_go_imports_handles_block_and_single() {
        let src = "package main\nimport \"fmt\"\nimport (\n\t\"net/http\"\n\t alias \"github.com/gin-gonic/gin\"\n)\n";
        let deps = extract_go_imports(src);
        assert!(deps.contains(&"fmt".to_owned()));
        assert!(deps.contains(&"net/http".to_owned()));
        assert!(deps.contains(&"github.com/gin-gonic/gin".to_owned()));
    }

    #[test]
    fn capture_returns_default_when_root_empty() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let spec = fake_spec("app.py", Lang::Python);
        let captured = capture_project_dependencies(root, &spec);
        assert!(captured.direct_deps.is_empty());
        assert!(captured.frameworks.is_empty());
        assert!(captured.lockfile.is_none());
        assert_eq!(captured.toolchain.toolchain_id, "python-3");
    }

    #[test]
    fn capture_picks_up_python_imports_and_frameworks() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::write(
            root.join("app.py"),
            "from flask import Flask, request\nimport os\nimport requests\n",
        )
        .unwrap();
        fs::write(root.join("requirements.txt"), "Flask==2.3.0\nrequests>=2.28\n").unwrap();
        let spec = fake_spec("app.py", Lang::Python);
        let captured = capture_project_dependencies(root, &spec);
        assert!(captured.direct_deps.contains(&"flask".to_owned()));
        assert!(captured.direct_deps.contains(&"requests".to_owned()));
        assert!(captured.frameworks.contains(&DetectedFramework::Flask));
        assert!(captured.lockfile.is_some());
    }

    #[test]
    fn stage_workdir_copies_entry_and_manifest() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::write(root.join("app.py"), "from flask import Flask\n").unwrap();
        fs::write(root.join("requirements.txt"), "Flask\n").unwrap();
        let spec = fake_spec("app.py", Lang::Python);
        let captured = capture_project_dependencies(root, &spec);
        let stage = TempDir::new().unwrap();
        let env = stage_workdir_with_spec_hash(&captured, stage.path(), "deadbeef").unwrap();
        assert!(env.workdir.join("app.py").is_file());
        assert!(env.workdir.join("requirements.txt").is_file());
        assert_eq!(env.spec_hash, "deadbeef");
        assert!(env.lockfile.is_some());
    }

    #[test]
    fn stage_workdir_respects_max_size() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // Write a single source over the budget. The copy must error.
        let big = vec![b'x'; (MAX_WORKDIR_BYTES + 1) as usize];
        fs::write(root.join("app.py"), &big).unwrap();
        let spec = fake_spec("app.py", Lang::Python);
        let captured = capture_project_dependencies(root, &spec);
        let stage = TempDir::new().unwrap();
        let err = stage_workdir(&captured, stage.path()).unwrap_err();
        assert!(err.to_string().contains("exceed"));
    }

    #[test]
    fn config_files_picked_up_when_present() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::write(root.join("app.py"), "from flask import Flask\n").unwrap();
        fs::write(root.join("config.yaml"), "debug: true\n").unwrap();
        fs::write(root.join(".env"), "FLASK_DEBUG=1\n").unwrap();
        let spec = fake_spec("app.py", Lang::Python);
        let captured = capture_project_dependencies(root, &spec);
        assert_eq!(captured.config_files.len(), 2);
    }
}
