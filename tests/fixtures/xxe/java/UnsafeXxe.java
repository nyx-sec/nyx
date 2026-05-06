// Unsafe: tainted XML reaches DocumentBuilder.parse without secure-processing
// configuration.  Class-qualified callee text (`javax.xml.parsers.DocumentBuilder.parse`)
// matches the flat XXE rule via suffix.
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
        return javax.xml.parsers.DocumentBuilder.parse(new ByteArrayInputStream(body.getBytes()));
    }
}
