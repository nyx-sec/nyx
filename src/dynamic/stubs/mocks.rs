//! Phase 19 (Track M.1) — language-specific mock generators for class
//! constructor parameters.
//!
//! When [`crate::dynamic::lang::LangEmitter::emit`] hits an
//! `EntryKind::ClassMethod` whose constructor takes an injectable
//! dependency (HTTP client, database connection, logger), the per-lang
//! emitter consults this registry to splice in a test double rather
//! than instantiating the real boundary.  The double is a tiny source
//! snippet — class / struct / function — that has the same surface as
//! the real type but performs no I/O.
//!
//! The registry is deliberately small: only the three dependency
//! shapes mentioned in Phase 19's brief
//! (`MockHttpClient`, `MockDatabaseConnection`, `MockLogger`) are
//! covered.  A future phase that needs richer doubles
//! (`MockCache`, `MockSessionStore`, …) can extend the [`MockKind`]
//! enum + add new branches to [`mock_source`] without re-versioning the
//! caller surface.

use crate::symbol::Lang;

/// Discriminator for an injectable dependency the harness may need to
/// stub when constructing a class receiver.
///
/// The names follow the Phase 19 brief verbatim.  Each variant maps to
/// one inline source snippet per language; the snippet declares a
/// constructor-callable type named `MockHttpClient` /
/// `MockDatabaseConnection` / `MockLogger` so the per-lang invocation
/// path can splice it in by name without needing a separate lookup
/// per language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MockKind {
    /// HTTP client surface — exposes `get` / `post` no-ops returning
    /// empty strings.
    HttpClient,
    /// Database connection surface — exposes `execute` / `query`
    /// no-ops returning empty result sets.
    DatabaseConnection,
    /// Logger surface — exposes `info` / `warn` / `error` no-ops.
    Logger,
}

impl MockKind {
    /// Canonical mock-type name a per-language emitter can construct.
    /// Stable across versions — call sites in lang emitters reference
    /// these strings directly.
    pub const fn type_name(self) -> &'static str {
        match self {
            Self::HttpClient => "MockHttpClient",
            Self::DatabaseConnection => "MockDatabaseConnection",
            Self::Logger => "MockLogger",
        }
    }
}

/// Source snippet declaring a `MockKind` test double in `lang`.
///
/// The snippet is meant to be spliced verbatim into the generated
/// harness source; it declares a public type whose name matches
/// [`MockKind::type_name`] and a public default constructor so the
/// harness's class-method dispatcher can write
/// `new {type_name}()` (or the per-lang equivalent) without further
/// per-mock plumbing.
///
/// Returns `""` (empty string) when the language has no concept of
/// classes / object dependencies (C, today).  The caller is expected
/// to fall through to a payload-only call when the snippet is empty.
pub fn mock_source(kind: MockKind, lang: Lang) -> &'static str {
    match (kind, lang) {
        // ── Python ──────────────────────────────────────────────────
        (MockKind::HttpClient, Lang::Python) => {
            "class MockHttpClient:\n    def get(self, url, **kw): return ''\n    def post(self, url, body=None, **kw): return ''\n"
        }
        (MockKind::DatabaseConnection, Lang::Python) => {
            "class MockDatabaseConnection:\n    def execute(self, q, *a, **kw): return None\n    def query(self, q, *a, **kw): return []\n    def close(self): pass\n"
        }
        (MockKind::Logger, Lang::Python) => {
            "class MockLogger:\n    def info(self, *a, **kw): pass\n    def warn(self, *a, **kw): pass\n    def error(self, *a, **kw): pass\n    def debug(self, *a, **kw): pass\n"
        }

        // ── JavaScript / TypeScript ────────────────────────────────
        (MockKind::HttpClient, Lang::JavaScript | Lang::TypeScript) => {
            "class MockHttpClient { get(_u){return ''} post(_u,_b){return ''} }\n"
        }
        (MockKind::DatabaseConnection, Lang::JavaScript | Lang::TypeScript) => {
            "class MockDatabaseConnection { execute(){return null} query(){return []} close(){} }\n"
        }
        (MockKind::Logger, Lang::JavaScript | Lang::TypeScript) => {
            "class MockLogger { info(){} warn(){} error(){} debug(){} }\n"
        }

        // ── Java ───────────────────────────────────────────────────
        (MockKind::HttpClient, Lang::Java) => {
            "static class MockHttpClient { public String get(String u){return \"\";} public String post(String u, String b){return \"\";} }\n"
        }
        (MockKind::DatabaseConnection, Lang::Java) => {
            "static class MockDatabaseConnection { public Object execute(String q){return null;} public java.util.List<Object> query(String q){return java.util.Collections.emptyList();} public void close(){} }\n"
        }
        (MockKind::Logger, Lang::Java) => {
            "static class MockLogger { public void info(String s){} public void warn(String s){} public void error(String s){} public void debug(String s){} }\n"
        }

        // ── PHP ────────────────────────────────────────────────────
        (MockKind::HttpClient, Lang::Php) => {
            "class MockHttpClient { public function get($u){return '';} public function post($u, $b = null){return '';} }\n"
        }
        (MockKind::DatabaseConnection, Lang::Php) => {
            "class MockDatabaseConnection { public function execute($q){return null;} public function query($q){return [];} public function close(){} }\n"
        }
        (MockKind::Logger, Lang::Php) => {
            "class MockLogger { public function info($m){} public function warn($m){} public function error($m){} public function debug($m){} }\n"
        }

        // ── Ruby ───────────────────────────────────────────────────
        (MockKind::HttpClient, Lang::Ruby) => {
            "class MockHttpClient\n  def get(_u); ''; end\n  def post(_u, _b = nil); ''; end\nend\n"
        }
        (MockKind::DatabaseConnection, Lang::Ruby) => {
            "class MockDatabaseConnection\n  def execute(_q); nil; end\n  def query(_q); []; end\n  def close; end\nend\n"
        }
        (MockKind::Logger, Lang::Ruby) => {
            "class MockLogger\n  def info(*); end\n  def warn(*); end\n  def error(*); end\n  def debug(*); end\nend\n"
        }

        // ── Go ─────────────────────────────────────────────────────
        // Go has no classes; we emit struct-shaped doubles with method
        // sets that mirror the Python / Java surface so a class-method
        // emitter can construct the receiver via `MockX{}`.
        (MockKind::HttpClient, Lang::Go) => {
            "type MockHttpClient struct{}\nfunc (MockHttpClient) Get(string) string { return \"\" }\nfunc (MockHttpClient) Post(string, string) string { return \"\" }\n"
        }
        (MockKind::DatabaseConnection, Lang::Go) => {
            "type MockDatabaseConnection struct{}\nfunc (MockDatabaseConnection) Execute(string) error { return nil }\nfunc (MockDatabaseConnection) Query(string) []interface{} { return nil }\nfunc (MockDatabaseConnection) Close() {}\n"
        }
        (MockKind::Logger, Lang::Go) => {
            "type MockLogger struct{}\nfunc (MockLogger) Info(string) {}\nfunc (MockLogger) Warn(string) {}\nfunc (MockLogger) Error(string) {}\nfunc (MockLogger) Debug(string) {}\n"
        }

        // ── Rust ───────────────────────────────────────────────────
        (MockKind::HttpClient, Lang::Rust) => {
            "pub struct MockHttpClient;\nimpl MockHttpClient { pub fn new() -> Self { MockHttpClient } pub fn get(&self, _u: &str) -> String { String::new() } pub fn post(&self, _u: &str, _b: &str) -> String { String::new() } }\n"
        }
        (MockKind::DatabaseConnection, Lang::Rust) => {
            "pub struct MockDatabaseConnection;\nimpl MockDatabaseConnection { pub fn new() -> Self { MockDatabaseConnection } pub fn execute(&self, _q: &str) {} pub fn query(&self, _q: &str) -> Vec<String> { Vec::new() } pub fn close(&self) {} }\n"
        }
        (MockKind::Logger, Lang::Rust) => {
            "pub struct MockLogger;\nimpl MockLogger { pub fn new() -> Self { MockLogger } pub fn info(&self, _m: &str) {} pub fn warn(&self, _m: &str) {} pub fn error(&self, _m: &str) {} pub fn debug(&self, _m: &str) {} }\n"
        }

        // ── C++ ────────────────────────────────────────────────────
        (MockKind::HttpClient, Lang::Cpp) => {
            "struct MockHttpClient { std::string get(const std::string&){return {};} std::string post(const std::string&, const std::string&){return {};} };\n"
        }
        (MockKind::DatabaseConnection, Lang::Cpp) => {
            "struct MockDatabaseConnection { void execute(const std::string&){} std::vector<std::string> query(const std::string&){return {};} void close(){} };\n"
        }
        (MockKind::Logger, Lang::Cpp) => {
            "struct MockLogger { void info(const std::string&){} void warn(const std::string&){} void error(const std::string&){} void debug(const std::string&){} };\n"
        }

        // ── C ──────────────────────────────────────────────────────
        // C has no class system; mocks are not applicable.  Lang emitter
        // routes `ClassMethod` to a plain function call when receiver
        // construction is meaningless.
        (_, Lang::C) => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_are_distinct_and_stable() {
        assert_eq!(MockKind::HttpClient.type_name(), "MockHttpClient");
        assert_eq!(
            MockKind::DatabaseConnection.type_name(),
            "MockDatabaseConnection"
        );
        assert_eq!(MockKind::Logger.type_name(), "MockLogger");
    }

    #[test]
    fn mock_source_python_declares_class() {
        let src = mock_source(MockKind::HttpClient, Lang::Python);
        assert!(src.contains("class MockHttpClient"));
        assert!(src.contains("def get"));
    }

    #[test]
    fn mock_source_java_uses_static_inner_class() {
        let src = mock_source(MockKind::Logger, Lang::Java);
        assert!(src.contains("static class MockLogger"));
        assert!(src.contains("public void info"));
    }

    #[test]
    fn mock_source_c_is_empty_no_class_system() {
        assert!(mock_source(MockKind::HttpClient, Lang::C).is_empty());
        assert!(mock_source(MockKind::DatabaseConnection, Lang::C).is_empty());
        assert!(mock_source(MockKind::Logger, Lang::C).is_empty());
    }

    #[test]
    fn mock_source_rust_struct_with_default_ctor() {
        let src = mock_source(MockKind::DatabaseConnection, Lang::Rust);
        assert!(src.contains("pub struct MockDatabaseConnection"));
        assert!(src.contains("pub fn new"));
    }

    #[test]
    fn mock_source_go_struct_with_method_set() {
        let src = mock_source(MockKind::HttpClient, Lang::Go);
        assert!(src.contains("type MockHttpClient struct"));
        assert!(src.contains("func (MockHttpClient) Get"));
    }

    #[test]
    fn every_lang_supports_every_mock_except_c() {
        for kind in [
            MockKind::HttpClient,
            MockKind::DatabaseConnection,
            MockKind::Logger,
        ] {
            for lang in [
                Lang::Python,
                Lang::JavaScript,
                Lang::TypeScript,
                Lang::Java,
                Lang::Php,
                Lang::Ruby,
                Lang::Go,
                Lang::Rust,
                Lang::Cpp,
            ] {
                assert!(
                    !mock_source(kind, lang).is_empty(),
                    "{lang:?} must supply a {kind:?} mock"
                );
            }
            assert!(mock_source(kind, Lang::C).is_empty());
        }
    }
}
