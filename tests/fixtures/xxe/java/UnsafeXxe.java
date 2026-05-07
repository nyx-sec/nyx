// Unsafe: tainted XML reaches DocumentBuilder.parse without secure-processing
// configuration.  The instance receiver `builder` carries TypeKind::XmlParser
// (Phase 07) so the type-qualified `XmlParser.parse` sink rule fires.
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;

public class UnsafeXxe {
    public Document handle(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(body.getBytes()));
    }
}
