import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeReflectionConstantMethod extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String handler = this.getClass().getMethod("list", HttpServletRequest.class).getName();
        String verb = request.getMethod();
        response.getWriter().println(handler.length() + verb.length());
    }

    public void list(HttpServletRequest r) {}
}
