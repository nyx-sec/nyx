import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FinallySinkAfterReturn extends HttpServlet {
    // The try body returns, and the finally clause still runs.
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String dir = req.getParameter("dir");
        try {
            return;
        } finally {
            Runtime.getRuntime().exec("rm -rf " + dir);
        }
    }

    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String dir = req.getParameter("dir");
        try {
            return;
        } finally {
            Runtime.getRuntime().exec("logrotate /etc/app.conf");
        }
    }
}
