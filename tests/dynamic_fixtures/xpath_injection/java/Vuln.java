// Phase 07 (Track J.5) — Java XPATH_INJECTION vuln fixture.
//
// The function string-concatenates the attacker-controlled `name`
// directly into an XPath expression evaluated by
// `javax.xml.xpath.XPath.evaluate`.  A payload like `alice' or '1'='1`
// rewraps the selector as `//user[@name='alice' or '1'='1']`,
// matching every <user> node in the staged document.
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class Vuln {
    public static Object run(String name) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse("xpath_corpus.xml");
        XPath xp = XPathFactory.newInstance().newXPath();
        String expr = "//user[@name='" + name + "']";
        return xp.evaluate(expr, doc, XPathConstants.NODESET);
    }
}
