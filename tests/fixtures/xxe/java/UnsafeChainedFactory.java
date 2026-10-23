// Unsafe: the builder is created and used in one expression, so the parse
// call reads as a call on the factory.  Neither form configures the factory.
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class UnsafeChainedFactory {
    public Document viaVariable(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(new InputSource(new StringReader(body)));
    }

    public Document viaStaticChain(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        return DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(new InputSource(new StringReader(body)));
    }
}
