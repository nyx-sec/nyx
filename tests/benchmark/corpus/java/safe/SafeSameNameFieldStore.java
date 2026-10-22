import javax.servlet.http.*;
import java.io.*;

public class SafeSameNameFieldStore extends HttpServlet {
    static class Holder { String path; }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String path = "/tmp/report.txt";
        Holder o = new Holder();
        o.path = req.getParameter("path");
        FileInputStream in = new FileInputStream(path);
        in.close();
    }
}
