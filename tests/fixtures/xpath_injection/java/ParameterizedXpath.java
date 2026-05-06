// Parameterised XPath: user input is bound via XPathVariableResolver
// (RFC-correct parameterisation) and the expression itself is a compile-time
// constant.  Even with the variable-resolver call preceding the evaluate(),
// the expression argument is not taint-bearing, so no XPATH_INJECTION
// finding fires.
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import javax.servlet.http.HttpServletRequest;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class ParameterizedXpath {
    public NodeList lookup(HttpServletRequest req, Document doc) throws Exception {
        final String user = req.getParameter("user");
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(new XPathVariableResolver() {
            public Object resolveVariable(QName name) {
                return user;
            }
        });
        return (NodeList) xpath.evaluate("//user[name=$u]", doc, XPathConstants.NODESET);
    }
}
