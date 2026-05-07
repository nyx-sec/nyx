// Unsafe: HttpServletResponse.setHeader receives a value built from a
// request parameter.  HEADER_INJECTION fires on the value argument.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UnsafeSetHeader {
    public void handle(HttpServletRequest req, HttpServletResponse res) {
        String lang = req.getParameter("lang");
        res.setHeader("X-Lang", lang);
    }
}
