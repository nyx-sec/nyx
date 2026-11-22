import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class XssBuilderChainEscapedSibling extends HttpServlet {
    // An escaper elsewhere in the chain does not clean the raw value.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String n = req.getParameter("n");
        StringBuilder sb = new StringBuilder();
        sb.append("a").append(n).append(StringEscapeUtils.escapeHtml4("x"));
        resp.getWriter().write(sb.toString());
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String n = req.getParameter("n");
        StringBuilder sb = new StringBuilder();
        sb.append(StringEscapeUtils.escapeHtml4(n)).append(n);
        resp.getWriter().write(sb.toString());
    }

    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String n = req.getParameter("n");
        StringBuilder sb = new StringBuilder();
        sb.append(StringEscapeUtils.escapeHtml4("x")).append(n);
        resp.getWriter().write(sb.toString());
    }
}
