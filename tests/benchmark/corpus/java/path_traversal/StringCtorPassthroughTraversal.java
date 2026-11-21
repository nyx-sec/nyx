import java.io.*;
import javax.servlet.http.*;

public class StringCtorPassthroughTraversal extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String param = req.getParameter("file");
        String fileName = new String(param.getBytes());
        FileInputStream fis = new FileInputStream(fileName);
        fis.transferTo(resp.getOutputStream());
        fis.close();
    }
}
