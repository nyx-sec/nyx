// Phase 14 fixture stub — minimal servlet request shape.
// Lives in the default package so the harness shim's
// `p.getName().endsWith("HttpServletRequest")` filter can match without
// a Maven dep on `jakarta.servlet-api`.

import java.util.HashMap;
import java.util.Map;

public class HttpServletRequest {
    private final Map<String, String> params = new HashMap<>();
    private String method = "GET";
    private String body = "";

    public void setParameter(String k, String v) { params.put(k, v); }
    public String getParameter(String k) { return params.get(k); }
    public void setMethod(String m) { this.method = m; }
    public String getMethod() { return method; }
    public void setBody(String b) { this.body = b; }
    public String getBody() { return body; }
}
