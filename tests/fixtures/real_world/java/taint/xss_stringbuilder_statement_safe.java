import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.apache.commons.text.StringEscapeUtils.escapeHtml4;

import org.apache.commons.text.StringEscapeUtils;

public class XssStringBuilderStatementSafe extends HttpServlet {
    // The value is escaped before it enters the builder.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        StringBuilder sb = new StringBuilder("<h1>");
        sb.append(StringEscapeUtils.escapeHtml4(name));
        sb.append("</h1>");
        resp.getWriter().write(sb.toString());
    }

    // Only constants are appended.
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String title = req.getParameter("title");
        StringBuffer page = new StringBuffer();
        page.append("<title>").append("fixed").append("</title>");
        resp.getWriter().println(page.toString());
    }

    // Static import of the escaper inside a chained builder statement.
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String label = req.getParameter("label");
        StringBuilder out = new StringBuilder();
        out.append("<p>").append(escapeHtml4(label)).append("</p>");
        resp.getWriter().write(out.toString());
    }
}
