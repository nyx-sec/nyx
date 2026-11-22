import io.netty.channel.DefaultFileRegion;
import io.netty.handler.stream.ChunkedFile;
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class PathTraversalNettyFileRegionSafe extends HttpServlet {
    private static final File ROOT = new File("/srv/static");

    // The request only chooses the length; the file is fixed.
    protected void doGet(HttpServletRequest req, javax.servlet.http.HttpServletResponse resp)
            throws IOException {
        long count = Long.parseLong(req.getParameter("count"));
        File f = new File(ROOT, "index.html");
        DefaultFileRegion region = new DefaultFileRegion(f, 0, count);
        ChunkedFile chunks = new ChunkedFile(f, 8192);
    }
}
