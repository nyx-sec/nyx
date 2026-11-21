import javax.servlet.http.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

public class XssJsoupParseEcho extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String raw = req.getParameter("html");
        Document doc = Jsoup.parse(raw);
        resp.getWriter().write(doc.html());
    }
}
