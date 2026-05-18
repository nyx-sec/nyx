// Phase 07 (Track J.5) — Java XPATH_INJECTION benign control fixture.
//
// Same shape as `Vuln.java` but routes the attacker-controlled `name`
// through a small XPath-string-literal escape helper before splicing
// it into the expression, so the selector stays pinned to a single
// node.
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class Benign {
    static String escapeXpathString(String s) {
        if (s.indexOf('\'') < 0) {
            return "'" + s + "'";
        }
        if (s.indexOf('"') < 0) {
            return "\"" + s + "\"";
        }
        return "concat('" + s.replace("'", "',\"'\",'") + "')";
    }

    public static Object run(String name) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse("xpath_corpus.xml");
        XPath xp = XPathFactory.newInstance().newXPath();
        String expr = "//user[@name=" + escapeXpathString(name) + "]";
        return xp.evaluate(expr, doc, XPathConstants.NODESET);
    }
}
