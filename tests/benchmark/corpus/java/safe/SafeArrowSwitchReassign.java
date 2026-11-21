import javax.servlet.http.*;
import java.io.IOException;

public class SafeArrowSwitchReassign extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        switch (req.getParameter("mode")) {
            case "list" -> cmd = "ls";
            default -> cmd = "date";
        }
        Runtime.getRuntime().exec(cmd);
    }
}
