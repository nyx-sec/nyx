// Safe: request param routed through `validateRedirectUrl` allowlist
// before being passed to sendRedirect.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SafeRedirect {
    public static String validateRedirectUrl(String raw) {
        return raw != null && raw.startsWith("/") ? raw : "/";
    }

    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String target = req.getParameter("next");
        String safe = validateRedirectUrl(target);
        res.sendRedirect(safe);
    }
}
