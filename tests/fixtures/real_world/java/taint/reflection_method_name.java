import java.lang.reflect.Method;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReflectionMethodName extends HttpServlet {
    // The request picks the method to call (Struts DispatchAction style).
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String action = request.getParameter("action");
        Method m = this.getClass().getMethod(action, HttpServletRequest.class);
        m.invoke(this, request);
    }

    // The same dispatch with a fixed name, and the servlet's own getMethod().
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Method m = this.getClass().getMethod("list", HttpServletRequest.class);
        m.invoke(this, request);
        String verb = request.getMethod();
        response.getWriter().println(verb.length());
    }

    public void list(HttpServletRequest r) {}
}
