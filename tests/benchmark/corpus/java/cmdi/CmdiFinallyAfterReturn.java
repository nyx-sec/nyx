import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// The try body returns, and the finally clause still runs.
public class CmdiFinallyAfterReturn extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String dir = req.getParameter("dir");
        try {
            return;
        } finally {
            Runtime.getRuntime().exec("rm -rf " + dir);
        }
    }
}
