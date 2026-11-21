// Inline relative-URL sanitiser.  Developer didn't extract
// `ensureRelativeUrl` into a named helper; the check is inline: a leading
// `/` plus a rejection of protocol-relative `//host`, so the redirect stays
// on-site and is not flagged.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SafeInlineRelative {
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String target = req.getParameter("next");
        if (target != null && target.startsWith("/") && !target.startsWith("//")) {
            res.sendRedirect(target);
        }
    }
}
