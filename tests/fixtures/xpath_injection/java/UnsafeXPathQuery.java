// Unsafe: attacker-controlled username concatenated into an XPath expression
// passed to XPath.evaluate.  The flat matcher catches the qualified call.
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import javax.servlet.http.HttpServletRequest;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class UnsafeXPathQuery {
    public NodeList lookup(HttpServletRequest req, Document doc) throws Exception {
        String user = req.getParameter("user");
        String expr = "//user[name='" + user + "']";
        XPath xpath = XPathFactory.newInstance().newXPath();
        return (NodeList) xpath.evaluate(expr, doc, XPathConstants.NODESET);
    }
}
