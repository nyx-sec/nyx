// Safe: the factory refuses DTDs and external entities before the reader is
// created, so the tainted document cannot pull in an entity.
import javax.servlet.http.HttpServletRequest;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.StringReader;

public class SafeStax {
    public String handle(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        XMLStreamReader reader = xif.createXMLStreamReader(new StringReader(body));
        reader.next();
        return reader.getLocalName();
    }
}
