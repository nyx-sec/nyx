import javax.servlet.http.*;
import java.io.PrintWriter;

public class AuditServlet extends HttpServlet {
    private void log(String msg) {
        System.out.println("[audit] " + msg);
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String user = req.getParameter("user");
        log(user);
        System.out.println("[audit] " + user);
        System.err.print(user);
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String user = req.getParameter("user");
        PrintWriter out = resp.getWriter();
        out.println(user);
    }
}

class WireFormat {
    static void println(PrintWriter pw, String s) {
        pw.print(s + "\r\n");
    }
}
