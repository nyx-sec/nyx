// Safe: tainted XML routed through a hardened DocumentBuilder.  The
// factory is configured with `FEATURE_SECURE_PROCESSING = true` before
// the builder is produced, and the produced builder inherits that
// hardening fact via the SSA xml-parser-config pass.  The downstream
// `builder.parse(...)` sink call therefore sees a secure receiver and
// the XXE bit is suppressed.
import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;

public class SafeXxeConfig {
    public Document handle(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(body.getBytes()));
    }
}
