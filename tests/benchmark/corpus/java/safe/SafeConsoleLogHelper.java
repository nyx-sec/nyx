import javax.servlet.http.*;

public class SafeConsoleLogHelper extends HttpServlet {
    private void audit(String msg) {
        System.out.println("[audit] " + msg);
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String user = req.getParameter("user");
        audit(user);
        System.err.println("login attempt: " + user);
    }
}
