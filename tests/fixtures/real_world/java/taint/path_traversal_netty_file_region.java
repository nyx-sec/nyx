import io.netty.channel.DefaultFileRegion;
import io.netty.handler.stream.ChunkedFile;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class PathTraversalNettyFileRegion extends HttpServlet {
    private static final File ROOT = new File("/srv/static");

    protected void doGet(HttpServletRequest req, javax.servlet.http.HttpServletResponse resp)
            throws IOException {
        String name = req.getParameter("file");
        File f = new File(ROOT, name);
        DefaultFileRegion region = new DefaultFileRegion(f, 0, f.length());
        ChunkedFile chunks = new ChunkedFile(f);
    }
}
