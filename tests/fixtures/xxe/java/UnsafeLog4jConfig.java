// Unsafe: Log4Shell-shape XXE leg.  The DOMConfigurator-style loader
// reads an XML config file path supplied by the user, then parses it
// through DocumentBuilder without enabling FEATURE_SECURE_PROCESSING or
// disallowing DOCTYPE declarations.  External entities resolve, giving
// the attacker a file-disclosure / SSRF primitive on the host.  Real-
// world precedent: CVE-2022-23305 / CVE-2022-23307 (Log4j 1.x JDBC /
// chainsaw config XXE).  Exercises the TypeFacts-tagged builder receiver
// + xml_config sidecar end-to-end: builder is XmlParser-typed, no
// secure-processing fact recorded, parse fires the XXE sink.
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.File;

public class UnsafeLog4jConfig {
    public Document loadConfig(HttpServletRequest req) throws Exception {
        String configPath = req.getParameter("config");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new File(configPath));
    }
}
