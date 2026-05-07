// Safe: request parameter routed through the project-local `stripCRLF`
// helper before being written to the response header.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeSetHeader {
    public static String stripCRLF(String raw) {
        return raw.replace("\r", "").replace("\n", "");
    }

    public void handle(HttpServletRequest req, HttpServletResponse res) {
        String lang = req.getParameter("lang");
        String safe = stripCRLF(lang);
        res.setHeader("X-Lang", safe);
    }
}
