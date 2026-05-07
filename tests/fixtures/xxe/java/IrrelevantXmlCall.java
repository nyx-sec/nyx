// Baseline: tainted body flows through a non-parser XML helper
// (StringBuilder concat).  No XML parser entry point, no XXE label
// classification.  Used to confirm taint-xxe doesn't fire on stray
// XML-adjacent string operations.
import javax.servlet.http.HttpServletRequest;

public class IrrelevantXmlCall {
    public String handle(HttpServletRequest req) {
        String body = req.getParameter("xml");
        StringBuilder sb = new StringBuilder("<wrap>");
        sb.append(body);
        sb.append("</wrap>");
        return sb.toString();
    }
}
