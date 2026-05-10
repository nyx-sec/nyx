// FP guard fixture: a final class field initialised with `Map.of(literal,
// literal, ...)` is an immutable allowlist whose `.get(taintedKey)` result
// is bounded to the literal value set.  Engine must NOT surface
// `taint-header-injection` on the safe handler.
//
// Mirrors CVE-2017-12629 (Apache Solr) patched counterpart: a pre-defined
// transformer name table prevents arbitrary downstream sinks from being
// reached by user-controlled data.
package com.example.fixtures;

import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeAllowlist extends HttpServlet {
    private static final Map<String, String> TRANSFORMERS = Map.of(
        "identity", "classpath:xslt/identity.xsl",
        "summary",  "classpath:xslt/summary.xsl"
    );

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String requested = req.getParameter("tr");
        String resolved = TRANSFORMERS.get(requested);
        if (resolved == null) {
            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        // Safe: `resolved` is one of the two literal values above; neither
        // contains CR/LF, so no header-injection sink can be reached.
        res.setHeader("X-Solr-Transform", resolved);
        res.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
