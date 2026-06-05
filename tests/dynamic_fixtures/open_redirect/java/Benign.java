// Phase 09 (Track J.7) — Java OPEN_REDIRECT benign control fixture.
//
// The function ignores the attacker-supplied value and always
// redirects to the same-origin path `/dashboard`, so the captured
// `Location:` header has no off-origin authority.
import javax.servlet.http.HttpServletResponse;

public class Benign {
    public static void run(HttpServletResponse response, String value) throws Exception {
        response.sendRedirect("/dashboard");
    }
}
