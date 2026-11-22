import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class XssBuilderChainAllEscaped extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String n = req.getParameter("n");
        StringBuilder sb = new StringBuilder();
        sb.append("a").append(StringEscapeUtils.escapeHtml4(n)).append(StringEscapeUtils.escapeHtml4("x"));
        resp.getWriter().write(sb.toString());
    }
}
