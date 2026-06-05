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
//! source for substring hits on `org.owasp.benchmark`,
//! `org.owasp.esapi`, or the narrow Spring helper packages used by
//! OWASP.  Non-OWASP harnesses pay zero workdir cost.

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
        (
            "org/apache/commons/lang/StringEscapeUtils.java".to_owned(),
            string_escape_utils_stub(),
        ),
    ]
}

/// Substring probe to decide whether an entry source pulls in the
/// OWASP Benchmark helper set.  Matches `org.owasp.benchmark` /
/// `org.owasp.esapi` references, and the small Spring helper packages
/// used by OWASP. Do not match generic Spring MVC annotations here:
/// real Spring controller fixtures bring those classes from Maven.
pub fn entry_needs_owasp_stubs(source: &str) -> bool {
    source.contains("org.owasp.benchmark")
        || source.contains("org.owasp.esapi")
        || source.contains("org.springframework.dao.")
        || source.contains("org.springframework.jdbc.")
        || source.contains("org.springframework.web.util.")
        || source.contains("org.apache.commons.lang.StringEscapeUtils")
}

fn utils_stub() -> String {
    // FIDELITY (Track L.12): the real `Utils.encodeForHTML` /
    // `htmlEscape` / `escapeHtml` delegate to a genuine HTML encoder
    // (`ESAPI.encoder().encodeForHTML` / Spring `HtmlUtils.htmlEscape`).
    // The verifier drives the real servlet with a live `<script>` payload,
    // so the stub MUST escape faithfully: a benign fixture that routes the
    // tainted value through one of these helpers neutralises the payload,
    // and a no-op stub would echo the marker raw and FALSE-CONFIRM.  Only
    // an unsanitised raw write (`getWriter().print(param)`) reaches the
    // response with the live marker.  `printOSCommandResults` streams the
    // child process's stdout/stderr to the response writer (and stdout) so
    // a CODE_EXEC marker echoed by an injected `echo` reaches the
    // OutputContains oracle.
    r#"package org.owasp.benchmark.helpers;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
public class Utils {
    // Faithful to the real helper (`user.dir + /testfiles/`); resolves to the
    // harness workdir's `testfiles/` because the Java harness runs with CWD =
    // workdir.  The FILE_IO path-traversal payload `../nyx_pt_canary` escapes
    // this one level to the workdir-root canary the emitter plants.
    public static String testfileDir =
        System.getProperty("user.dir") + java.io.File.separator + "testfiles" + java.io.File.separator;
    static String nyxEscapeHtml(String s) {
        if (s == null) return "";
        StringBuilder o = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '&': o.append("&amp;"); break;
                case '<': o.append("&lt;"); break;
                case '>': o.append("&gt;"); break;
                case '"': o.append("&quot;"); break;
                case '\'': o.append("&#x27;"); break;
                case '/': o.append("&#x2f;"); break;
                default: o.append(ch);
            }
        }
        return o.toString();
    }
    public static String encodeForHTML(Object param) {
        return param == null ? "" : nyxEscapeHtml(String.valueOf(param));
    }
    public static String escapeHtml(String s) { return nyxEscapeHtml(s); }
    public static String htmlEscape(String s) { return nyxEscapeHtml(s); }
    public static String getFileFromClasspath(String name, ClassLoader cl) { return name; }
    public static String getInsecureOSCommandString(ClassLoader cl) { return "/bin/sh"; }
    public static String getOSCommandString(String cmd) { return cmd == null ? "/bin/sh" : cmd; }
    public static void printOSCommandResults(Process p, Object response) {
        StringBuilder out = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = r.readLine()) != null) { out.append(line).append('\n'); }
        } catch (IOException ignore) {}
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
            String line;
            while ((line = r.readLine()) != null) { out.append(line).append('\n'); }
        } catch (IOException ignore) {}
        String text = out.toString();
        System.out.print(text);
        if (response != null) {
            try {
                Object w = response.getClass().getMethod("getWriter").invoke(response);
                w.getClass().getMethod("write", String.class).invoke(w, text);
            } catch (Exception ignore) {}
        }
        try { p.waitFor(); } catch (InterruptedException ignore) {}
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
    // FIDELITY (Track L.12): the real `SeparateClassRequest` wraps the
    // servlet request.  `getTheParameter` / `getTheCookie` are TAINTED
    // sources (delegate to the request, which the Nyx stub firehoses with
    // the payload); `getTheValue` is a SAFE source — the real helper
    // returns the constant `"bar"` regardless of input, so benign fixtures
    // that read through `getTheValue` must NOT receive the payload (else
    // they false-confirm).  Delegating to the (firehosed) request keeps the
    // tainted accessors live while the constant keeps the safe one safe.
    r#"package org.owasp.benchmark.helpers;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
public class SeparateClassRequest {
    private HttpServletRequest request;
    public SeparateClassRequest(HttpServletRequest request) { this.request = request; }
    public String getTheParameter(String p) { return request == null ? null : request.getParameter(p); }
    public String getTheCookie(String c) {
        if (request == null) return "";
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(c)) { return cookie.getValue(); }
            }
        }
        return "";
    }
    // Safe source: the real helper hard-codes this return.
    public String getTheValue(String p) { return "bar"; }
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
    // FIDELITY (Track L.12): `ESAPI.encoder().encodeForHTML` is a REAL
    // HTML encoder in upstream ESAPI.  OWASP benign fixtures (and the
    // incidental `getWriter().write(ESAPI.encoder().encodeForHTML(fileName))`
    // echoes in path-traversal / crypto fixtures) rely on it neutralising
    // metacharacters.  A no-op stub would let a firehosed `<script>` marker
    // through and FALSE-CONFIRM xss on those files, so the stub escapes
    // `& < > " ' /` exactly like the real encoder's HTML context.
    r#"package org.owasp.esapi;
public class ESAPI {
    private static final Encoder ENCODER = new Encoder() {
        @Override public String encodeForHTML(String s) {
            if (s == null) return "";
            StringBuilder o = new StringBuilder(s.length() + 16);
            for (int i = 0; i < s.length(); i++) {
                char ch = s.charAt(i);
                switch (ch) {
                    case '&': o.append("&amp;"); break;
                    case '<': o.append("&lt;"); break;
                    case '>': o.append("&gt;"); break;
                    case '"': o.append("&quot;"); break;
                    case '\'': o.append("&#x27;"); break;
                    case '/': o.append("&#x2f;"); break;
                    default: o.append(ch);
                }
            }
            return o.toString();
        }
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

fn string_escape_utils_stub() -> String {
    // FIDELITY (Track L.12): Apache Commons Lang `StringEscapeUtils.escapeHtml`
    // is a real HTML encoder used as the XSS defence in benign OWASP fixtures
    // (`org.apache.commons.lang.StringEscapeUtils.escapeHtml(param)`, inline
    // FQN).  Without the stub javac reports the package missing → BuildFailed;
    // with a faithful escape a benign escape path neutralises the marker.
    r#"package org.apache.commons.lang;
public class StringEscapeUtils {
    public static String escapeHtml(String s) {
        if (s == null) return null;
        StringBuilder o = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '&': o.append("&amp;"); break;
                case '<': o.append("&lt;"); break;
                case '>': o.append("&gt;"); break;
                case '"': o.append("&quot;"); break;
                default: o.append(ch);
            }
        }
        return o.toString();
    }
    public static String unescapeHtml(String s) { return s; }
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
    // FIDELITY (Track L.12): Spring `HtmlUtils.htmlEscape` is a real HTML
    // encoder; benign OWASP fixtures use it as the XSS defence.  Escape
    // faithfully so a firehosed `<script>` marker cannot survive a benign
    // escape path and false-confirm.
    r#"package org.springframework.web.util;
public class HtmlUtils {
    public static String htmlEscape(String s) {
        if (s == null) return "";
        StringBuilder o = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '&': o.append("&amp;"); break;
                case '<': o.append("&lt;"); break;
                case '>': o.append("&gt;"); break;
                case '"': o.append("&quot;"); break;
                case '\'': o.append("&#39;"); break;
                default: o.append(ch);
            }
        }
        return o.toString();
    }
    public static String htmlEscape(String s, String enc) { return htmlEscape(s); }
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
            "org/apache/commons/lang/StringEscapeUtils.java",
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
            14,
            "expected 9 owasp + 4 springframework + 1 commons-lang stub"
        );
    }
}
