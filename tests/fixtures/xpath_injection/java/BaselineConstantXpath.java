// Baseline: expression is a compile-time constant.  No taint reaches
// `xpath.evaluate` so no XPATH_INJECTION finding fires.
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class BaselineConstantXpath {
    public NodeList lookup(Document doc) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return (NodeList) xpath.evaluate("//user[@role='admin']", doc, XPathConstants.NODESET);
    }
}
