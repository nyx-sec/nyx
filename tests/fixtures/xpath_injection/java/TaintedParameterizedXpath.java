// Tainted-expression-with-resolver: user input flows into the XPath
// expression argument, but the receiver was bound to an
// XPathVariableResolver before the evaluate() call.  Phase 03's
// name-only `setXPathVariableResolver` sanitizer rule would not have
// suppressed this (the rule fires on the resolver-binding call, which
// has no flow-tied taint to clear).  The receiver-config sidecar in
// `src/ssa/xpath_config.rs` flips `has_resolver` on the bound XPath
// instance and the SSA sink-emission site strips XPATH_INJECTION from
// any later evaluate() on that receiver.
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import javax.servlet.http.HttpServletRequest;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class TaintedParameterizedXpath {
    public NodeList lookup(HttpServletRequest req, Document doc) throws Exception {
        final String user = req.getParameter("user");
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(new XPathVariableResolver() {
            public Object resolveVariable(QName name) {
                return user;
            }
        });
        // Tainted expression interpolation: user bypasses the resolver
        // and reaches `evaluate` directly.  Real-world parameterised
        // XPath would use a constant expression with `$u` here, but the
        // engineering decision modelled by the sidecar is: a bound
        // resolver indicates intended parameterisation, so suppress.
        String expr = "//user[name='" + user + "']";
        return (NodeList) xpath.evaluate(expr, doc, XPathConstants.NODESET);
    }
}
