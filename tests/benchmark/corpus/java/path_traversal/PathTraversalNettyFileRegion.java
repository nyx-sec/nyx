import io.netty.channel.DefaultFileRegion;
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathTraversalNettyFileRegion extends HttpServlet {
    private static final File ROOT = new File("/srv/static");

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("file");
        File f = new File(ROOT, name);
        DefaultFileRegion region = new DefaultFileRegion(f, 0, f.length());
    }
}
