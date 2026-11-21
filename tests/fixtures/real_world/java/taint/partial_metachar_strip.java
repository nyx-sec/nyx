import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PartialMetacharStrip extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String host = req.getParameter("host");
        host = host.replaceAll("|", "");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
