// Phase 21 (Track M.3) — Spring HandlerInterceptor middleware vuln
// fixture.
//
// `Vuln#preHandle` splices the request body into a shell command via
// Runtime.exec.  HandlerInterceptor is referenced as a substring
// marker only.
//
// implements HandlerInterceptor

public class Vuln {
    public boolean preHandle(String payload) throws Exception {
        // SINK: tainted payload concatenated into shell command.
        Runtime.getRuntime().exec(new String[] { "/bin/sh", "-c", "echo " + payload });
        return true;
    }
}
