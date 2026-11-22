import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;

public class SafeStringBuilderEscapedAppend extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        StringBuilder sb = new StringBuilder("<h1>");
        sb.append(StringEscapeUtils.escapeHtml4(name));
        sb.append("</h1>");
        resp.getWriter().write(sb.toString());
    }
}
