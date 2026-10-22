import java.io.*;
import javax.servlet.http.*;

public class SafeFileCtorSanitized extends HttpServlet {
    static String sanitizePath(String s) {
        if (s.contains("..") || s.startsWith("/") || s.startsWith("\\")) {
            return "";
        }
        return s;
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        String safe = sanitizePath(name);
        File f = new File("/var/data", safe);
        FileInputStream in = new FileInputStream(f);
        in.transferTo(resp.getOutputStream());
        in.close();
    }
}
