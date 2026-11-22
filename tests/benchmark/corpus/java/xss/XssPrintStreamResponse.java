import java.io.DataOutputStream;
import java.io.PrintStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PrintStreamOnResponse extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        PrintStream ps = new PrintStream(resp.getOutputStream());
        ps.println("<b>" + req.getParameter("n"));
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        DataOutputStream d = new DataOutputStream(resp.getOutputStream());
        d.write(req.getParameter("n").getBytes());
    }
}
