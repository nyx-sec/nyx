// Phase 09 (Track J.7) — Java OPEN_REDIRECT vuln fixture.
//
// The function passes `value` straight into
// `HttpServletResponse.sendRedirect` without host validation.  A
// payload carrying `https://attacker.test/` sends the response's
// `Location:` header off-origin.
import javax.servlet.http.HttpServletResponse;

public class Vuln {
    public static void run(HttpServletResponse response, String value) throws Exception {
        response.sendRedirect(value);
    }
}
