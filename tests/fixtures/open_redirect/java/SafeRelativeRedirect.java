// Safe: request param routed through `ensureRelativeUrl` which enforces a
// leading `/` and rejects scheme-prefixed values (relative-only path).
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SafeRelativeRedirect {
    public static String ensureRelativeUrl(String raw) {
        if (raw == null || !raw.startsWith("/") || raw.startsWith("//")) {
            return "/";
        }
        return raw;
    }

    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String target = req.getParameter("next");
        String safe = ensureRelativeUrl(target);
        res.sendRedirect(safe);
    }
}
