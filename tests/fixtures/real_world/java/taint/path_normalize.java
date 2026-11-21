import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathNormalize extends HttpServlet {
    private static final Path BASE = Paths.get("/srv/files");

    // Vulnerable: normalize is lexical, `../../etc/passwd` survives resolve.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Path p = BASE.resolve(name).normalize();
        byte[] data = Files.readAllBytes(p);
        resp.setStatus(200);
    }

    // Safe: normalize, then a containment check against the base.
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Path p = BASE.resolve(name).normalize();
        if (!p.startsWith(BASE)) {
            throw new SecurityException("outside the base directory");
        }
        byte[] data = Files.readAllBytes(p);
        resp.setStatus(200);
    }
}
