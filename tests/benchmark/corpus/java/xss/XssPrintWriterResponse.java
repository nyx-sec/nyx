import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class XssPrintWriterResponse extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String q = req.getParameter("q");
        PrintWriter w = resp.getWriter();
        w.println("<p>" + q + "</p>");
    }
}
