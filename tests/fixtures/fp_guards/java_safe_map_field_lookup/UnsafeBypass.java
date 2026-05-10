// Recall guard counterpart: when the field initializer is NOT a recognised
// safe `Map.of(literal, literal, ...)` shape (here, the value position is
// constructed dynamically from a separate request parameter), the engine
// must still surface the header-injection flow.
package com.example.fixtures;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UnsafeBypass extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
        // Pure passthrough: tainted parameter flows directly to the header
        // value with no allowlist gate.
        String value = req.getParameter("v");
        res.setHeader("X-Echo", value);
    }
}
