// Unsafe: HttpServletResponse.sendRedirect receives a request-supplied URL.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UnsafeRedirect {
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String target = req.getParameter("next");
        res.sendRedirect(target);
    }
}
