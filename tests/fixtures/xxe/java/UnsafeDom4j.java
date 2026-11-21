// Unsafe: dom4j's SAXReader resolves external entities by default.
import javax.servlet.http.HttpServletRequest;
import org.dom4j.Document;
import org.dom4j.io.SAXReader;
import java.io.StringReader;

public class UnsafeDom4j {
    public Document handle(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        SAXReader reader = new SAXReader();
        return reader.read(new StringReader(body));
    }
}
