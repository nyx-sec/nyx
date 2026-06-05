// Phase 08 (Track J.6) — Java HEADER_INJECTION vuln fixture.
//
// The function string-concatenates the attacker-controlled `value`
// directly into a `Set-Cookie` header set via
// `HttpServletResponse.setHeader`.  A payload carrying `\r\nSet-Cookie:
// nyx-injected=pwn` splits the single header into two on the wire.
import javax.servlet.http.HttpServletResponse;

public class Vuln {
    public static void run(HttpServletResponse response, String value) {
        response.setHeader("Set-Cookie", value);
    }
}
