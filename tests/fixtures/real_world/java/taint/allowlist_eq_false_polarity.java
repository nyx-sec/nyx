import java.io.IOException;
import java.util.Set;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AllowlistEqFalsePolarity extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("ls", "pwd");

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        if (ALLOWED.contains(cmd) == false) {
            return;
        }
        Runtime.getRuntime().exec(cmd);
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        if (ALLOWED.contains(cmd) == false) {
            Runtime.getRuntime().exec(cmd);
        }
    }
}
