import javax.servlet.http.*;

// `n += 1` makes n 6, so the branch runs.  Lowering `n += 1` as the
// constant 1 would prune it and hide the flow.
public class CmdiCounterBranch extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = req.getParameter("cmd");
        int n = 5;
        n += 1;
        if (n > 5) {
            Runtime.getRuntime().exec(cmd);
        }
    }
}
