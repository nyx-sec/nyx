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

use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// `FuncSummary`.
    pub fn from_extension(ext: &str) -> Option<Lang> {
        match ext {
            "rs" => Some(Lang::Rust),
            "c" => Some(Lang::C),
            "cpp" => Some(Lang::Cpp),
            "java" => Some(Lang::Java),
            "go" => Some(Lang::Go),
            "php" => Some(Lang::Php),
            "py" => Some(Lang::Python),
            "ts" => Some(Lang::TypeScript),
            "js" => Some(Lang::JavaScript),
            "rb" => Some(Lang::Ruby),
            _ => None,
        }
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
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuncKey {
    pub lang: Lang,
    /// Project-relative file path (e.g. `"src/lib.rs"`).
    pub namespace: String,
    /// Enclosing container path (class / impl / module / nested function).
    /// Empty for free top-level functions.  Segments joined with `::`.
    #[serde(default)]
    pub container: String,
    pub name: String,
    pub arity: Option<usize>,
    /// Numeric discriminator for same-name siblings (closures, duplicate defs).
    /// Typically the function node's start byte offset.
    #[serde(default)]
    pub disambig: Option<u32>,
    /// Structural role, Function, Method, Constructor, Closure, etc.
    #[serde(default)]
    pub kind: FuncKind,
}

impl FuncKey {
    /// Construct a plain free-function key (no container, no disambig).
    /// Kept as a convenience for call sites and tests that do not need the
    /// extra discriminators.
    pub fn new_function(
        lang: Lang,
        namespace: impl Into<String>,
        name: impl Into<String>,
        arity: Option<usize>,
    ) -> Self {
        FuncKey {
            lang,
            namespace: namespace.into(),
            container: String::new(),
            name: name.into(),
            arity,
            disambig: None,
            kind: FuncKind::Function,
        }
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

#[cfg(test)]
mod tests;
