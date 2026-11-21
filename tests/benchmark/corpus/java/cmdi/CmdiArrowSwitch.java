import javax.servlet.http.*;
import java.io.IOException;

public class CmdiArrowSwitch extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        switch (req.getParameter("mode")) {
            case "run" -> Runtime.getRuntime().exec(cmd);
            default -> resp.getWriter().write("no");
        }
    }
}
