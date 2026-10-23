// Unsafe: tainted XML reaches a StAX reader built from a default
// XMLInputFactory.  DTDs and external entities are on unless the factory is
// told otherwise, and StAX parses straight off the factory.
import javax.servlet.http.HttpServletRequest;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.StringReader;

public class UnsafeStax {
    public String handle(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        XMLInputFactory xif = XMLInputFactory.newInstance();
        XMLStreamReader reader = xif.createXMLStreamReader(new StringReader(body));
        reader.next();
        return reader.getLocalName();
    }
}
