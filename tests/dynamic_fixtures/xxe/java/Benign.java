// Phase 05 (Track J.3) — Java XXE benign fixture.
//
// Same parser surface as `vuln.java` but the factory is hardened with
// `disallow-doctype-decl`, so the same payload's `<!ENTITY>` block is
// rejected at parse time and no entity body is substituted.
import java.io.ByteArrayInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class Benign {
    public static Document run(byte[] payload) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(payload));
    }
}
