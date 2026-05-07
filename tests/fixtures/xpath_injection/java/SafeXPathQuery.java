// Safe: user-supplied substring routed through the project-local
// `escapeXpath` helper before being concatenated into the XPath expression.
// The sanitizer clears the XPATH_INJECTION cap so the sink does not fire.
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import javax.servlet.http.HttpServletRequest;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class SafeXPathQuery {
    public static String escapeXpath(String raw) {
        return raw.replace("'", "&apos;");
    }

    public NodeList lookup(HttpServletRequest req, Document doc) throws Exception {
        String user = req.getParameter("user");
        String safe = escapeXpath(user);
        String expr = "//user[name='" + safe + "']";
        XPath xpath = XPathFactory.newInstance().newXPath();
        return (NodeList) xpath.evaluate(expr, doc, XPathConstants.NODESET);
    }
}
