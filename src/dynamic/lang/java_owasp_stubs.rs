//! Minimal `org.owasp.benchmark.helpers`, `org.owasp.esapi`, and Spring
//! shim stubs for Java harnesses against OWASP Benchmark v1.2 fixtures.
//!
//! OWASP Benchmark testcases lean on a handful of helper classes that
//! ship with the upstream Maven project but are not on the harness
//! workdir classpath.  Without them `javac` reports
//! `error: package org.owasp.benchmark.helpers does not exist` (and
//! the matching `esapi` / `springframework` variants) and the verifier
//! flips to `BuildFailed` before any sink probe runs.
//!
//! The bundle here covers the surface OWASP Benchmark v1.2 fixtures
//! actually reference (verified by walking
//! `~/.cache/nyx/eval_corpus/owasp_benchmark_v1.2/`):
//!
//! * `org.owasp.benchmark.helpers.Utils` — `testfileDir` field plus
//!   the encode / OS-command helpers.
//! * `org.owasp.benchmark.helpers.DatabaseHelper` — `JDBCtemplate`
//!   field of stub `BenchmarkJdbcTemplate` type, plus the
//!   `getSqlConnection` / `getSqlStatement` / `printResults` family.
//! * `org.owasp.benchmark.helpers.LDAPManager` — directory-context
//!   handle pair.
//! * `org.owasp.benchmark.helpers.SeparateClassRequest` — wraps a
//!   `javax.servlet.http.HttpServletRequest` and exposes
//!   `getTheParameter` / `getTheValue`.
//! * `org.owasp.benchmark.helpers.ThingFactory` / `ThingInterface` —
//!   reflection-style indirection used by reflection-shape fixtures.
//! * `org.owasp.esapi.ESAPI` / `org.owasp.esapi.Encoder` — the
//!   `ESAPI.encoder().encodeForHTML(...)` / `encodeForBase64(...)`
//!   pair.
//! * `org.springframework.dao.DataAccessException` —
//!   `RowMapper.mapRow` throws it.
//! * `org.springframework.jdbc.core.RowMapper` — anonymous-impl
//!   target.
//! * `org.springframework.jdbc.support.rowset.SqlRowSet` — return
//!   type of `JDBCtemplate.queryForRowSet`.
//! * `org.springframework.web.util.HtmlUtils` — `htmlEscape` static.
//!
//! Methods return null / empty defaults; runtime correctness past the
//! `javac` link step is the job of the spec-derivation fallback
//! paths, not the build-time stubs.
//!
//! Detection gate ([`entry_needs_owasp_stubs`]) checks the entry
//! source for substring hits on `org.owasp.benchmark` /
//! `org.owasp.esapi` / `org.springframework`.  Non-OWASP harnesses
//! pay zero workdir cost.

/// Returns `(workdir_relative_path, file_content)` pairs ready to
/// drop into [`crate::dynamic::lang::HarnessSource::extra_files`].
/// Always returns the full bundle; callers gate on
/// [`entry_needs_owasp_stubs`] when scoping is desired.
pub fn owasp_stub_files() -> Vec<(String, String)> {
    vec![
        (
            "org/owasp/benchmark/helpers/Utils.java".to_owned(),
            utils_stub(),
        ),
        (
            "org/owasp/benchmark/helpers/DatabaseHelper.java".to_owned(),
            database_helper_stub(),
        ),
        (
            "org/owasp/benchmark/helpers/BenchmarkJdbcTemplate.java".to_owned(),
            benchmark_jdbc_template_stub(),
        ),
        (
            "org/owasp/benchmark/helpers/LDAPManager.java".to_owned(),
            ldap_manager_stub(),
        ),
        (
            "org/owasp/benchmark/helpers/SeparateClassRequest.java".to_owned(),
            separate_class_request_stub(),
        ),
        (
            "org/owasp/benchmark/helpers/ThingFactory.java".to_owned(),
            thing_factory_stub(),
        ),
        (
            "org/owasp/benchmark/helpers/ThingInterface.java".to_owned(),
            thing_interface_stub(),
        ),
        ("org/owasp/esapi/ESAPI.java".to_owned(), esapi_stub()),
        ("org/owasp/esapi/Encoder.java".to_owned(), encoder_stub()),
        (
            "org/springframework/dao/DataAccessException.java".to_owned(),
            data_access_exception_stub(),
        ),
        (
            "org/springframework/jdbc/core/RowMapper.java".to_owned(),
            row_mapper_stub(),
        ),
        (
            "org/springframework/jdbc/support/rowset/SqlRowSet.java".to_owned(),
            sql_row_set_stub(),
        ),
        (
            "org/springframework/web/util/HtmlUtils.java".to_owned(),
            html_utils_stub(),
        ),
    ]
}

/// Substring probe to decide whether an entry source pulls in the
/// OWASP Benchmark helper set.  Matches `org.owasp.benchmark` /
/// `org.owasp.esapi` / `org.springframework` references, including
/// import statements and inline FQNs.  Conservative on false
/// positives: a fixture that only mentions one of these in a comment
/// will still get the stubs staged, which is harmless javac work.
pub fn entry_needs_owasp_stubs(source: &str) -> bool {
    source.contains("org.owasp.benchmark")
        || source.contains("org.owasp.esapi")
        || source.contains("org.springframework")
}

fn utils_stub() -> String {
    r#"package org.owasp.benchmark.helpers;
import java.io.IOException;
import java.io.InputStream;
public class Utils {
    public static String testfileDir = "/tmp/testfiles/";
    public static String encodeForHTML(String s) { return s == null ? "" : s; }
    public static String escapeHtml(String s) { return s == null ? "" : s; }
    public static String htmlEscape(String s) { return s == null ? "" : s; }
    public static String getFileFromClasspath(String name, ClassLoader cl) { return name; }
    public static String getInsecureOSCommandString(ClassLoader cl) { return "/bin/sh"; }
    public static String getOSCommandString(String cmd) { return cmd == null ? "/bin/sh" : cmd; }
    public static void printOSCommandResults(Process p, Object response) {
        try {
            InputStream is = p.getInputStream();
            if (is != null) { is.close(); }
        } catch (IOException ignore) {}
    }
}
"#
    .to_owned()
}

fn database_helper_stub() -> String {
    r#"package org.owasp.benchmark.helpers;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
public class DatabaseHelper {
    public static boolean hideSQLErrors = false;
    public static BenchmarkJdbcTemplate JDBCtemplate = new BenchmarkJdbcTemplate();
    public static Connection getSqlConnection() throws SQLException { return null; }
    public static Statement getSqlStatement() throws SQLException { return null; }
    public static void printResults(ResultSet rs, String sql, Object response) throws SQLException {}
    public static void printResults(Statement statement, String sql, Object response) throws SQLException {}
    public static void outputUpdateComplete(String sql, Object response) {}
}
"#
    .to_owned()
}

fn benchmark_jdbc_template_stub() -> String {
    // Names the small JdbcTemplate-shaped surface OWASP fixtures call
    // off `DatabaseHelper.JDBCtemplate`.  Real Spring JdbcTemplate
    // ships in spring-jdbc; this stub keeps the link step succeeding
    // without dragging that jar in.
    r#"package org.owasp.benchmark.helpers;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.rowset.SqlRowSet;
public class BenchmarkJdbcTemplate {
    public int queryForInt(String sql) { return 0; }
    public Long queryForLong(String sql) { return 0L; }
    public List<?> queryForList(String sql) { return Collections.emptyList(); }
    public Map<String, Object> queryForMap(String sql) { return Collections.emptyMap(); }
    public <T> T queryForObject(String sql, Object[] args, Class<T> requiredType) { return null; }
    public SqlRowSet queryForRowSet(String sql) { return null; }
    public <T> List<T> query(String sql, RowMapper<T> mapper) { return Collections.emptyList(); }
    public int[] batchUpdate(String sql) { return new int[0]; }
    public void execute(String sql) {}
}
"#
    .to_owned()
}

fn ldap_manager_stub() -> String {
    r#"package org.owasp.benchmark.helpers;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
public class LDAPManager {
    public LDAPManager() {}
    public DirContext getDirContext() throws NamingException { return null; }
    public void closeDirContext() {}
}
"#
    .to_owned()
}

fn separate_class_request_stub() -> String {
    // Real SeparateClassRequest wraps a servlet request and delegates
    // getTheParameter / getTheValue through to it; the stub keeps the
    // public surface but discards the request reference.
    r#"package org.owasp.benchmark.helpers;
import javax.servlet.http.HttpServletRequest;
public class SeparateClassRequest {
    public SeparateClassRequest(HttpServletRequest request) {}
    public String getTheParameter(String name) { return null; }
    public String getTheValue(String name) { return null; }
}
"#
    .to_owned()
}

fn thing_factory_stub() -> String {
    r#"package org.owasp.benchmark.helpers;
public class ThingFactory {
    public static ThingInterface createThing() {
        return new ThingInterface() {
            @Override public String doSomething(String input) { return input; }
        };
    }
}
"#
    .to_owned()
}

fn thing_interface_stub() -> String {
    r#"package org.owasp.benchmark.helpers;
public interface ThingInterface {
    String doSomething(String input);
}
"#
    .to_owned()
}

fn esapi_stub() -> String {
    r#"package org.owasp.esapi;
public class ESAPI {
    private static final Encoder ENCODER = new Encoder() {
        @Override public String encodeForHTML(String s) { return s == null ? "" : s; }
        @Override public String encodeForBase64(byte[] b, boolean wrap) {
            return b == null ? "" : java.util.Base64.getEncoder().encodeToString(b);
        }
    };
    public static Encoder encoder() { return ENCODER; }
}
"#
    .to_owned()
}

fn encoder_stub() -> String {
    r#"package org.owasp.esapi;
public interface Encoder {
    String encodeForHTML(String s);
    String encodeForBase64(byte[] b, boolean wrap);
}
"#
    .to_owned()
}

fn data_access_exception_stub() -> String {
    r#"package org.springframework.dao;
public class DataAccessException extends RuntimeException {
    public DataAccessException(String msg) { super(msg); }
    public DataAccessException(String msg, Throwable cause) { super(msg, cause); }
}
"#
    .to_owned()
}

fn row_mapper_stub() -> String {
    r#"package org.springframework.jdbc.core;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.dao.DataAccessException;
public interface RowMapper<T> {
    T mapRow(ResultSet rs, int rowNum) throws SQLException, DataAccessException;
}
"#
    .to_owned()
}

fn sql_row_set_stub() -> String {
    r#"package org.springframework.jdbc.support.rowset;
public interface SqlRowSet {
    boolean next();
    String getString(int columnIndex);
    String getString(String columnLabel);
    int getInt(int columnIndex);
    int getInt(String columnLabel);
    Object getObject(int columnIndex);
    Object getObject(String columnLabel);
}
"#
    .to_owned()
}

fn html_utils_stub() -> String {
    r#"package org.springframework.web.util;
public class HtmlUtils {
    public static String htmlEscape(String s) { return s == null ? "" : s; }
    public static String htmlUnescape(String s) { return s == null ? "" : s; }
}
"#
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_needs_owasp_stubs_detects_helper_imports() {
        let src = "package x;\nimport org.owasp.benchmark.helpers.Utils;\npublic class V {}\n";
        assert!(entry_needs_owasp_stubs(src));
    }

    #[test]
    fn entry_needs_owasp_stubs_detects_esapi_imports() {
        let src = "import org.owasp.esapi.ESAPI;\npublic class V {}\n";
        assert!(entry_needs_owasp_stubs(src));
    }

    #[test]
    fn entry_needs_owasp_stubs_detects_spring_imports() {
        let src = "import org.springframework.web.util.HtmlUtils;\n";
        assert!(entry_needs_owasp_stubs(src));
    }

    #[test]
    fn entry_needs_owasp_stubs_detects_inline_fqn() {
        // OWASP fixtures often use inline FQNs without an import line.
        let src = "public class V { void f() { org.owasp.esapi.ESAPI.encoder(); } }";
        assert!(entry_needs_owasp_stubs(src));
    }

    #[test]
    fn entry_needs_owasp_stubs_rejects_non_owasp_source() {
        let src = "public class V { void f() { System.out.println(\"hi\"); } }";
        assert!(!entry_needs_owasp_stubs(src));
    }

    #[test]
    fn bundle_includes_owasp_helpers() {
        let paths: Vec<String> = owasp_stub_files().into_iter().map(|(p, _)| p).collect();
        for required in &[
            "org/owasp/benchmark/helpers/Utils.java",
            "org/owasp/benchmark/helpers/DatabaseHelper.java",
            "org/owasp/benchmark/helpers/BenchmarkJdbcTemplate.java",
            "org/owasp/benchmark/helpers/LDAPManager.java",
            "org/owasp/benchmark/helpers/SeparateClassRequest.java",
            "org/owasp/benchmark/helpers/ThingFactory.java",
            "org/owasp/benchmark/helpers/ThingInterface.java",
            "org/owasp/esapi/ESAPI.java",
            "org/owasp/esapi/Encoder.java",
            "org/springframework/dao/DataAccessException.java",
            "org/springframework/jdbc/core/RowMapper.java",
            "org/springframework/jdbc/support/rowset/SqlRowSet.java",
            "org/springframework/web/util/HtmlUtils.java",
        ] {
            assert!(
                paths.iter().any(|p| p == required),
                "owasp stub bundle missing {required}; got {paths:?}",
            );
        }
    }

    #[test]
    fn utils_stub_carries_owasp_method_surface() {
        let src = utils_stub();
        for method in &[
            "testfileDir",
            "encodeForHTML",
            "escapeHtml",
            "htmlEscape",
            "getFileFromClasspath",
            "getInsecureOSCommandString",
            "getOSCommandString",
            "printOSCommandResults",
        ] {
            assert!(
                src.contains(method),
                "Utils stub missing OWASP surface member `{method}`",
            );
        }
    }

    #[test]
    fn database_helper_stub_carries_owasp_method_surface() {
        let src = database_helper_stub();
        for method in &[
            "hideSQLErrors",
            "JDBCtemplate",
            "getSqlConnection",
            "getSqlStatement",
            "printResults",
            "outputUpdateComplete",
        ] {
            assert!(
                src.contains(method),
                "DatabaseHelper stub missing OWASP surface member `{method}`",
            );
        }
    }

    #[test]
    fn benchmark_jdbc_template_carries_call_surface() {
        let src = benchmark_jdbc_template_stub();
        for method in &[
            "queryForInt",
            "queryForLong",
            "queryForList",
            "queryForMap",
            "queryForObject",
            "queryForRowSet",
            "query",
            "batchUpdate",
            "execute",
        ] {
            assert!(
                src.contains(method),
                "BenchmarkJdbcTemplate stub missing OWASP surface member `{method}`",
            );
        }
    }

    #[test]
    fn encoder_stub_declares_two_encode_methods() {
        let src = encoder_stub();
        assert!(src.contains("encodeForHTML"));
        assert!(src.contains("encodeForBase64"));
    }

    #[test]
    fn esapi_stub_returns_anonymous_encoder() {
        let src = esapi_stub();
        assert!(src.contains("public static Encoder encoder()"));
        assert!(src.contains("new Encoder()"));
    }

    #[test]
    fn separate_class_request_takes_servlet_request() {
        let src = separate_class_request_stub();
        assert!(src.contains("javax.servlet.http.HttpServletRequest"));
        assert!(src.contains("getTheParameter"));
        assert!(src.contains("getTheValue"));
    }

    #[test]
    fn bundle_has_thirteen_files() {
        // Tripwire: 9 OWASP-namespace + 4 spring-namespace stubs.  A
        // count drift here usually means a stub was added without
        // updating the assertion or a stub got accidentally dropped.
        let files = owasp_stub_files();
        assert_eq!(
            files.len(),
            13,
            "expected 9 owasp + 4 springframework stubs"
        );
    }
}
