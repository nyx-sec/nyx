import javax.servlet.http.*;

public class ContextPathRedirectSafe {
    public void doAct(HttpServletRequest req, HttpServletResponse rsp) throws java.io.IOException {
        if (req.getParameter("no") != null) {
            rsp.sendRedirect(req.getContextPath() + "/manage");
        } else {
            rsp.sendRedirect(req.getContextPath() + "/configureSecurity");
        }
    }
}
