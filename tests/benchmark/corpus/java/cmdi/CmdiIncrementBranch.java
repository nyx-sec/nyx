import javax.servlet.http.*;

// `i++` makes i 1, so the branch runs.  Without the increment as a
// definition, `i == 1` folded false against the initial 0.
public class CmdiIncrementBranch extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = req.getParameter("cmd");
        int i = 0;
        i++;
        if (i == 1) {
            Runtime.getRuntime().exec(cmd);
        }
    }
}
