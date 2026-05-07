// Safe counterpart to UnsafeLog4jConfig.java: DOMConfigurator-style XML
// config loader, hardened by setting FEATURE_SECURE_PROCESSING + the
// disallow-doctype-decl feature on the factory before the builder is
// produced.  The xml_config sidecar records the hardening fact on the
// factory's SSA value, propagates it to the builder via
// `newDocumentBuilder()`, and the parse sink suppresses the XXE bit.
import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.File;

public class SafeLog4jConfig {
    public Document loadConfig(HttpServletRequest req) throws Exception {
        String configPath = req.getParameter("config");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new File(configPath));
    }
}
