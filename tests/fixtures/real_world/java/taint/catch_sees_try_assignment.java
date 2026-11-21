import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CatchSeesTryAssignment extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = "ls";
        if (req.getHeader("x-verbose") != null) {
            resp.setStatus(200);
        }
        try {
            cmd = req.getParameter("cmd");
            check(cmd);
        } catch (Exception e) {
            Runtime.getRuntime().exec(cmd);
        }
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = "ls";
        if (req.getHeader("x-verbose") != null) {
            resp.setStatus(200);
        }
        try {
            cmd = "pwd";
            check(cmd);
        } catch (Exception e) {
            Runtime.getRuntime().exec(cmd);
        }
    }

    private void check(String s) throws Exception {}
}
