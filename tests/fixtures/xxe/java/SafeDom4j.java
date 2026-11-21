// Safe: the OWASP cheat-sheet hardening for dom4j, with the feature name as
// an inline string literal.
import javax.servlet.http.HttpServletRequest;
import org.dom4j.Document;
import org.dom4j.io.SAXReader;
import java.io.StringReader;

public class SafeDom4j {
    public Document handle(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        SAXReader reader = new SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return reader.read(new StringReader(body));
    }
}
