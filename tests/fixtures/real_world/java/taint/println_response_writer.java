import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PrintlnResponseWriter extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        PrintWriter w = resp.getWriter();
        w.println("<p>" + req.getParameter("q") + "</p>");
    }
}
