// Unsafe: a leading-slash check alone lets `?next=//evil.example` through,
// which the browser follows as a protocol-relative URL.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UnsafeInlineSlashOnly {
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String target = req.getParameter("next");
        if (target != null && target.startsWith("/")) {
            res.sendRedirect(target);
        }
    }
}
