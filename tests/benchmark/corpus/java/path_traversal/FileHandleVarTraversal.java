import java.io.*;
import javax.servlet.http.*;

public class FileHandleVarTraversal extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        File dest = new File("/srv/uploads", name);
        FileOutputStream out = new FileOutputStream(dest);
        req.getInputStream().transferTo(out);
        out.close();
    }
}
