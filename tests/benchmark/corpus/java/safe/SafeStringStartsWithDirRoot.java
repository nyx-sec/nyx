import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// The root ends with a separator, so "/srv/data-old/x" fails the prefix test.
public class SafeStringStartsWithDirRoot extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String f = req.getParameter("f");
        Path p = Paths.get(f).normalize();
        if (!p.toString().startsWith("/srv/data/")) {
            throw new SecurityException("outside the root");
        }
        new FileInputStream(p.toFile());
    }
}
