// Safe: only the inline-literal disallow-doctype-decl feature, no
// XMLConstants identifier.  The feature name has no SSA value, so the
// hardening is read from the call's literal arguments.
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;

public class SafeXxeLiteralFeature {
    public Document handle(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(body.getBytes()));
    }
}
