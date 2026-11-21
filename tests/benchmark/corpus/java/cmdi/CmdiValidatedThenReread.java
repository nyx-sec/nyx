import javax.servlet.http.*;
import java.io.*;

public class CmdiValidatedThenReread extends HttpServlet {
    static boolean isValidName(String s) { return s.matches("[a-z]+"); }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        if (!isValidName(name)) {
            resp.sendError(400);
            return;
        }
        name = req.getParameter("other");
        Runtime.getRuntime().exec("echo " + name);
    }
}
