// Safe: no XML parser sink reached, body just stored.  Used as a baseline
// to confirm taint-xxe does not fire when the dangerous API is absent.
import javax.servlet.http.HttpServletRequest;

public class SafeXxe {
    public String handle(HttpServletRequest req) {
        String body = req.getParameter("xml");
        return body.length() > 0 ? body : "empty";
    }
}
