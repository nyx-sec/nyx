// Phase 05 (Track J.3) — Java XXE vuln fixture.
//
// The function feeds attacker bytes to a stock `DocumentBuilderFactory`
// without setting `disallow-doctype-decl` / `XMLConstants.FEATURE_
// SECURE_PROCESSING`, so any `<!ENTITY xxe SYSTEM "file:///…">`
// declaration in the payload is resolved and its body substituted
// into the parsed tree.
import java.io.ByteArrayInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class Vuln {
    public static Document run(byte[] payload) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(payload));
    }
}
