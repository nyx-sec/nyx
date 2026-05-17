//! Minimal `javax.servlet` and `jakarta.servlet` stubs for Java harnesses.
//!
//! Many real-world Java codebases (OWASP Benchmark, Spring servlet adapters,
//! legacy webapps) carry `import javax.servlet.http.HttpServletRequest;` or
//! the `jakarta.servlet` counterpart in source files the dynamic verifier
//! wants to compile.  Without these symbols on the classpath, `javac` emits
//! `error: package javax.servlet does not exist` and the verifier reports
//! `BuildFailed` before any sink probe runs.
//!
//! The stubs here cover the surface the harness actually needs to link:
//! a no-arg-constructible `HttpServletRequest` whose `setParameter` /
//! `setMethod` / `setBody` setters slot into the reflective adapter in
//! `SERVLET_HELPER`, plus the small set of getters that OWASP Benchmark
//! fixtures call (`getCookies`, `getHeader`, `getInputStream`, `getReader`,
//! `getParameter`, `getParameterMap`, `getParameterNames`,
//! `getParameterValues`, `getQueryString`, `getSession`).  Methods return
//! null / empty defaults; runtime correctness past compilation is the job
//! of the spec-derivation fallback paths, not the build-time stubs.
//!
//! The bundle ships both `javax.servlet` and `jakarta.servlet` so source
//! files predating the EE 9 rename and source files using the new
//! namespace both link.  Each stub is generated from the same template via
//! [`make_servlet_stubs`] so the two trees stay in sync.

/// Stub bundle for the servlet-shape Java harnesses.
///
/// Returns `(workdir_relative_path, file_content)` pairs ready to drop into
/// [`crate::dynamic::lang::HarnessSource::extra_files`].  Subdirectories in
/// the path are created by the harness builder; the bundled files live
/// under `javax/servlet/...` and `jakarta/servlet/...` so `javac -d <out>`
/// drops the resulting `.class` files into matching package directories
/// and the entry source's `import javax.servlet.http.HttpServletRequest;`
/// resolves at compile time.
pub fn servlet_stub_files() -> Vec<(String, String)> {
    let mut out = make_servlet_stubs("javax.servlet");
    out.extend(make_servlet_stubs("jakarta.servlet"));
    out
}

/// Render the nine-file stub set under the given package prefix
/// (`javax.servlet` or `jakarta.servlet`).
fn make_servlet_stubs(pkg: &str) -> Vec<(String, String)> {
    let pkg_path = pkg.replace('.', "/");
    let http = format!("{pkg}.http");
    let http_path = format!("{pkg_path}/http");
    vec![
        (
            format!("{pkg_path}/ServletException.java"),
            servlet_exception(pkg),
        ),
        (
            format!("{pkg_path}/ServletInputStream.java"),
            servlet_input_stream(pkg),
        ),
        (
            format!("{pkg_path}/RequestDispatcher.java"),
            request_dispatcher(pkg, &http),
        ),
        (
            format!("{pkg_path}/annotation/WebServlet.java"),
            web_servlet(pkg),
        ),
        (format!("{http_path}/HttpServlet.java"), http_servlet(pkg)),
        (
            format!("{http_path}/HttpServletRequest.java"),
            http_servlet_request(pkg, &http),
        ),
        (
            format!("{http_path}/HttpServletResponse.java"),
            http_servlet_response(&http),
        ),
        (
            format!("{http_path}/HttpSession.java"),
            http_session(&http),
        ),
        (format!("{http_path}/Cookie.java"), cookie(&http)),
    ]
}

fn servlet_exception(pkg: &str) -> String {
    format!(
        r#"package {pkg};
public class ServletException extends Exception {{
    public ServletException() {{ super(); }}
    public ServletException(String msg) {{ super(msg); }}
    public ServletException(String msg, Throwable cause) {{ super(msg, cause); }}
    public ServletException(Throwable cause) {{ super(cause); }}
}}
"#
    )
}

fn servlet_input_stream(pkg: &str) -> String {
    format!(
        r#"package {pkg};
import java.io.InputStream;
import java.io.IOException;
public abstract class ServletInputStream extends InputStream {{
    protected ServletInputStream() {{}}
    @Override public int read() throws IOException {{ return -1; }}
}}
"#
    )
}

fn request_dispatcher(pkg: &str, http: &str) -> String {
    format!(
        r#"package {pkg};
import {http}.HttpServletRequest;
import {http}.HttpServletResponse;
import java.io.IOException;
public interface RequestDispatcher {{
    void forward(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException;
    void include(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException;
}}
"#
    )
}

fn web_servlet(pkg: &str) -> String {
    format!(
        r#"package {pkg}.annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface WebServlet {{
    String[] value() default {{}};
    String[] urlPatterns() default {{}};
    String name() default "";
    int loadOnStartup() default -1;
    boolean asyncSupported() default false;
}}
"#
    )
}

fn http_servlet(pkg: &str) -> String {
    format!(
        r#"package {pkg}.http;
import {pkg}.ServletException;
import java.io.IOException;
public abstract class HttpServlet {{
    public HttpServlet() {{}}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {{}}
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {{}}
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {{}}
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {{}}
    protected void doHead(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {{}}
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {{}}
    protected void doTrace(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {{}}
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {{}}
    public String getServletInfo() {{ return ""; }}
    public void init() throws ServletException {{}}
    public void destroy() {{}}
}}
"#
    )
}

fn http_servlet_request(pkg: &str, http: &str) -> String {
    format!(
        r#"package {http};
import {pkg}.RequestDispatcher;
import {pkg}.ServletInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
public class HttpServletRequest {{
    private final Map<String, String> params = new HashMap<>();
    private String method = "GET";
    private String body = "";
    public HttpServletRequest() {{}}
    public void setParameter(String name, String value) {{ params.put(name, value); }}
    public void setMethod(String m) {{ this.method = m; }}
    public void setBody(String b) {{ this.body = b == null ? "" : b; }}
    public String getBody() {{ return body; }}
    public String getParameter(String name) {{ return params.get(name); }}
    public String[] getParameterValues(String name) {{
        String v = params.get(name);
        return v == null ? null : new String[] {{ v }};
    }}
    public Map<String, String[]> getParameterMap() {{
        Map<String, String[]> m = new HashMap<>();
        for (Map.Entry<String, String> e : params.entrySet()) {{
            m.put(e.getKey(), new String[] {{ e.getValue() }});
        }}
        return m;
    }}
    public Enumeration<String> getParameterNames() {{ return Collections.enumeration(params.keySet()); }}
    public String getHeader(String name) {{ return null; }}
    public Enumeration<String> getHeaders(String name) {{ return Collections.emptyEnumeration(); }}
    public Enumeration<String> getHeaderNames() {{ return Collections.emptyEnumeration(); }}
    public int getIntHeader(String name) {{ return -1; }}
    public long getDateHeader(String name) {{ return -1L; }}
    public Cookie[] getCookies() {{ return null; }}
    public HttpSession getSession() {{ return new HttpSession(); }}
    public HttpSession getSession(boolean create) {{ return new HttpSession(); }}
    public ServletInputStream getInputStream() throws IOException {{ return null; }}
    public BufferedReader getReader() throws IOException {{ return new BufferedReader(new StringReader(body)); }}
    public String getMethod() {{ return method; }}
    public String getQueryString() {{ return null; }}
    public StringBuffer getRequestURL() {{ return new StringBuffer(); }}
    public String getRequestURI() {{ return ""; }}
    public String getRemoteAddr() {{ return "127.0.0.1"; }}
    public String getRemoteHost() {{ return "localhost"; }}
    public String getServletPath() {{ return ""; }}
    public String getContextPath() {{ return ""; }}
    public String getPathInfo() {{ return null; }}
    public String getPathTranslated() {{ return null; }}
    public Object getAttribute(String name) {{ return null; }}
    public void setAttribute(String name, Object value) {{}}
    public void removeAttribute(String name) {{}}
    public Enumeration<String> getAttributeNames() {{ return Collections.emptyEnumeration(); }}
    public String getCharacterEncoding() {{ return "UTF-8"; }}
    public void setCharacterEncoding(String enc) {{}}
    public String getContentType() {{ return null; }}
    public int getContentLength() {{ return body == null ? 0 : body.length(); }}
    public long getContentLengthLong() {{ return getContentLength(); }}
    public String getProtocol() {{ return "HTTP/1.1"; }}
    public String getScheme() {{ return "http"; }}
    public String getServerName() {{ return "localhost"; }}
    public int getServerPort() {{ return 80; }}
    public Locale getLocale() {{ return Locale.getDefault(); }}
    public Enumeration<Locale> getLocales() {{ return Collections.enumeration(Collections.singletonList(Locale.getDefault())); }}
    public RequestDispatcher getRequestDispatcher(String path) {{ return null; }}
    public boolean isSecure() {{ return false; }}
    public String getAuthType() {{ return null; }}
    public String getRemoteUser() {{ return null; }}
    public java.security.Principal getUserPrincipal() {{ return null; }}
    public boolean isUserInRole(String role) {{ return false; }}
    public String getRequestedSessionId() {{ return null; }}
    public boolean isRequestedSessionIdValid() {{ return false; }}
    public boolean isRequestedSessionIdFromCookie() {{ return false; }}
    public boolean isRequestedSessionIdFromURL() {{ return false; }}
}}
"#
    )
}

fn http_servlet_response(http: &str) -> String {
    format!(
        r#"package {http};
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
public class HttpServletResponse {{
    public static final int SC_OK = 200;
    public static final int SC_NOT_FOUND = 404;
    public static final int SC_FORBIDDEN = 403;
    public static final int SC_UNAUTHORIZED = 401;
    public static final int SC_INTERNAL_SERVER_ERROR = 500;
    public static final int SC_MOVED_PERMANENTLY = 301;
    public static final int SC_MOVED_TEMPORARILY = 302;
    private final StringWriter sw = new StringWriter();
    private final PrintWriter pw = new PrintWriter(sw);
    private int status = SC_OK;
    public HttpServletResponse() {{}}
    public PrintWriter getWriter() throws IOException {{ return pw; }}
    public String getBody() {{ pw.flush(); return sw.toString(); }}
    public OutputStream getOutputStream() throws IOException {{ return new java.io.ByteArrayOutputStream(); }}
    public void setContentType(String type) {{}}
    public String getContentType() {{ return null; }}
    public void setCharacterEncoding(String enc) {{}}
    public String getCharacterEncoding() {{ return "UTF-8"; }}
    public void setContentLength(int len) {{}}
    public void setContentLengthLong(long len) {{}}
    public void setStatus(int sc) {{ this.status = sc; }}
    public int getStatus() {{ return status; }}
    public void sendError(int sc) throws IOException {{ this.status = sc; }}
    public void sendError(int sc, String msg) throws IOException {{ this.status = sc; }}
    public void sendRedirect(String location) throws IOException {{ this.status = SC_MOVED_TEMPORARILY; }}
    public void addCookie(Cookie cookie) {{}}
    public void setHeader(String name, String value) {{}}
    public void addHeader(String name, String value) {{}}
    public void setIntHeader(String name, int value) {{}}
    public void addIntHeader(String name, int value) {{}}
    public void setDateHeader(String name, long date) {{}}
    public void addDateHeader(String name, long date) {{}}
    public boolean containsHeader(String name) {{ return false; }}
    public String getHeader(String name) {{ return null; }}
    public java.util.Collection<String> getHeaders(String name) {{ return java.util.Collections.emptyList(); }}
    public java.util.Collection<String> getHeaderNames() {{ return java.util.Collections.emptyList(); }}
    public String encodeURL(String url) {{ return url; }}
    public String encodeRedirectURL(String url) {{ return url; }}
    public void flushBuffer() throws IOException {{}}
    public void resetBuffer() {{}}
    public void reset() {{}}
    public boolean isCommitted() {{ return false; }}
    public void setBufferSize(int size) {{}}
    public int getBufferSize() {{ return 0; }}
    public void setLocale(java.util.Locale loc) {{}}
    public java.util.Locale getLocale() {{ return java.util.Locale.getDefault(); }}
}}
"#
    )
}

fn http_session(http: &str) -> String {
    format!(
        r#"package {http};
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
public class HttpSession {{
    private final Map<String, Object> attrs = new HashMap<>();
    public HttpSession() {{}}
    public String getId() {{ return "stub-session"; }}
    public void setAttribute(String name, Object value) {{ attrs.put(name, value); }}
    public Object getAttribute(String name) {{ return attrs.get(name); }}
    public void removeAttribute(String name) {{ attrs.remove(name); }}
    public Enumeration<String> getAttributeNames() {{ return Collections.enumeration(attrs.keySet()); }}
    public long getCreationTime() {{ return 0L; }}
    public long getLastAccessedTime() {{ return 0L; }}
    public int getMaxInactiveInterval() {{ return 0; }}
    public void setMaxInactiveInterval(int interval) {{}}
    public boolean isNew() {{ return true; }}
    public void invalidate() {{}}
    public void putValue(String name, Object value) {{ attrs.put(name, value); }}
    public Object getValue(String name) {{ return attrs.get(name); }}
    public String[] getValueNames() {{ return attrs.keySet().toArray(new String[0]); }}
    public void removeValue(String name) {{ attrs.remove(name); }}
}}
"#
    )
}

fn cookie(http: &str) -> String {
    format!(
        r#"package {http};
public class Cookie implements Cloneable {{
    private String name;
    private String value;
    private String path;
    private String domain;
    private String comment;
    private int maxAge = -1;
    private int version = 0;
    private boolean secure;
    private boolean httpOnly;
    public Cookie() {{}}
    public Cookie(String name, String value) {{ this.name = name; this.value = value; }}
    public String getName() {{ return name; }}
    public String getValue() {{ return value; }}
    public void setValue(String value) {{ this.value = value; }}
    public void setPath(String path) {{ this.path = path; }}
    public String getPath() {{ return path; }}
    public void setDomain(String domain) {{ this.domain = domain; }}
    public String getDomain() {{ return domain; }}
    public void setMaxAge(int age) {{ this.maxAge = age; }}
    public int getMaxAge() {{ return maxAge; }}
    public void setSecure(boolean secure) {{ this.secure = secure; }}
    public boolean getSecure() {{ return secure; }}
    public void setHttpOnly(boolean httpOnly) {{ this.httpOnly = httpOnly; }}
    public boolean isHttpOnly() {{ return httpOnly; }}
    public void setVersion(int v) {{ this.version = v; }}
    public int getVersion() {{ return version; }}
    public void setComment(String c) {{ this.comment = c; }}
    public String getComment() {{ return comment; }}
    @Override public Object clone() {{ try {{ return super.clone(); }} catch (CloneNotSupportedException e) {{ throw new RuntimeException(e); }} }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ships_both_javax_and_jakarta_trees() {
        let files = servlet_stub_files();
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"javax/servlet/http/HttpServletRequest.java"));
        assert!(paths.contains(&"javax/servlet/ServletException.java"));
        assert!(paths.contains(&"javax/servlet/annotation/WebServlet.java"));
        assert!(paths.contains(&"jakarta/servlet/http/HttpServletRequest.java"));
        assert!(paths.contains(&"jakarta/servlet/ServletException.java"));
        assert!(paths.contains(&"jakarta/servlet/annotation/WebServlet.java"));
    }

    #[test]
    fn bundle_has_eighteen_files() {
        // Nine stubs per package tree, two trees.  A drift here usually
        // means a stub was added without updating the count assertion or
        // a stub got accidentally dropped.
        let files = servlet_stub_files();
        assert_eq!(files.len(), 18, "expected 9 javax + 9 jakarta stubs");
    }

    #[test]
    fn http_servlet_request_carries_owasp_method_surface() {
        // OWASP Benchmark v1.2 fixtures exercise this surface; if any of
        // these getters disappears the bundle will start producing
        // BuildFailed verdicts on the corresponding fixtures.
        let req = http_servlet_request("javax.servlet", "javax.servlet.http");
        for method in &[
            "getCookies",
            "getHeader",
            "getHeaderNames",
            "getHeaders",
            "getInputStream",
            "getParameter",
            "getParameterMap",
            "getParameterNames",
            "getParameterValues",
            "getQueryString",
            "getSession",
            "getReader",
        ] {
            assert!(
                req.contains(method),
                "javax HttpServletRequest stub missing `{method}`"
            );
        }
    }

    #[test]
    fn http_servlet_response_carries_owasp_method_surface() {
        let resp = http_servlet_response("javax.servlet.http");
        for method in &["addCookie", "getWriter", "setContentType"] {
            assert!(
                resp.contains(method),
                "javax HttpServletResponse stub missing `{method}`"
            );
        }
    }

    #[test]
    fn http_servlet_request_keeps_reflective_hook_setters() {
        // The Java emitter's SERVLET_HELPER uses reflection to invoke
        // setParameter / setMethod / setBody on the stub request before
        // the entry method runs.  Dropping any of these would silently
        // break payload seeding for OWASP-shape harnesses.
        for pkg in &["javax.servlet", "jakarta.servlet"] {
            let http = format!("{pkg}.http");
            let req = http_servlet_request(pkg, &http);
            for method in &["setParameter", "setMethod", "setBody"] {
                assert!(
                    req.contains(method),
                    "{pkg} HttpServletRequest stub missing `{method}`"
                );
            }
        }
    }

    #[test]
    fn jakarta_stubs_carry_jakarta_package_declaration() {
        let files = servlet_stub_files();
        for (path, body) in &files {
            if path.starts_with("jakarta/") {
                assert!(
                    body.contains("package jakarta.servlet"),
                    "jakarta stub at {path} missing jakarta package declaration"
                );
                assert!(
                    !body.contains("package javax.servlet"),
                    "jakarta stub at {path} accidentally carries javax package"
                );
            }
        }
    }
}
