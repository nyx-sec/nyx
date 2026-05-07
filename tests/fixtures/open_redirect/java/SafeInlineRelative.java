// Phase 05 follow-up: inline relative-URL sanitiser.  Developer didn't
// extract `ensureRelativeUrl` into a named helper; the leading-slash
// check is inline.  RelativeUrlValidated predicate strips OPEN_REDIRECT
// on the true branch so the redirect call is not flagged.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SafeInlineRelative {
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String target = req.getParameter("next");
        if (target != null && target.startsWith("/")) {
            res.sendRedirect(target);
        }
    }
}
