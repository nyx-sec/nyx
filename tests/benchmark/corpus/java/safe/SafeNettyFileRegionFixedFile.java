import io.netty.channel.DefaultFileRegion;
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeNettyFileRegionFixedFile extends HttpServlet {
    private static final File ROOT = new File("/srv/static");

    // The request only chooses the byte count; the file is fixed.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        long count = Long.parseLong(req.getParameter("count"));
        File f = new File(ROOT, "index.html");
        DefaultFileRegion region = new DefaultFileRegion(f, 0, count);
    }
}
