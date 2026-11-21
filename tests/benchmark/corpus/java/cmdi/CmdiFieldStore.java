import javax.servlet.http.*;

public class CmdiFieldStore extends HttpServlet {
    static class Holder { String cmd; }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        Holder o = new Holder();
        o.cmd = req.getParameter("cmd");
        Runtime.getRuntime().exec(o.cmd);
    }
}
