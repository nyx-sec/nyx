import java.lang.reflect.Method;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReflectionMethodName extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String action = request.getParameter("action");
        Method m = this.getClass().getMethod(action, HttpServletRequest.class);
        m.invoke(this, request);
    }

    public void list(HttpServletRequest r) {}
}
