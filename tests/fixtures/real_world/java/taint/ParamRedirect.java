import javax.servlet.http.*;

public class ParamRedirect {
    public void doAct(HttpServletRequest req, HttpServletResponse rsp) throws java.io.IOException {
        rsp.sendRedirect(req.getParameter("next"));
    }
}
