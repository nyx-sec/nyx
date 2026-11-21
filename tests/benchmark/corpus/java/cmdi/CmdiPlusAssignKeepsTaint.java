import javax.servlet.http.*;

// Appending a literal flag with `+=` keeps the request value in `cmd`.
public class CmdiPlusAssignKeepsTaint extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = req.getParameter("cmd");
        cmd += " --verbose";
        Runtime.getRuntime().exec(cmd);
    }
}
