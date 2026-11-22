import java.net.URL;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SsrfUrlContextResolution extends HttpServlet {
    // Vulnerable: `new URL(context, "//evil/x")` resolves to the attacker's host.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String spec = req.getParameter("spec");
        URL base = new URL("https://api.example.com/");
        URL target = new URL(base, spec);
        target.openStream();
    }

    // Safe: a fixed `v1/` head is a relative reference.
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String id = req.getParameter("id");
        URL base = new URL("https://api.example.com/");
        URL target = new URL(base, "v1/items/" + id);
        target.openStream();
    }
}
