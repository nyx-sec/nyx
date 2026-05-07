// Safe: parser variable reassigned across a branch; both branches harden
// the receiver before reaching `parse`, so the SSA phi-meet preserves
// the secure_processing fact.  Validates Phase 07 acceptance:
// "Config fact correctly survives intra-procedural reassignment of the
// parser variable through SSA phi."
import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;

public class SafeXxePhi {
    public Document handle(HttpServletRequest req, boolean useAlternate) throws Exception {
        String body = req.getParameter("xml");
        DocumentBuilderFactory factory;
        if (useAlternate) {
            factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } else {
            factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        }
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(body.getBytes()));
    }
}
