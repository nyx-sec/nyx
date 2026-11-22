import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Path.startsWith compares components and is exact for any root.
 * String.startsWith is byte-wise, so a root without a trailing separator
 * admits a sibling directory.
 */
public class PathContainmentStringRoot extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String f = req.getParameter("f");
        Path p = Paths.get(f).normalize();
        if (!p.startsWith("/srv/data")) {
            throw new SecurityException("outside the root");
        }
        new FileInputStream(p.toFile()); // @safe Path.startsWith compares components
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String f = req.getParameter("f");
        Path p = Paths.get(f).normalize();
        if (!p.toString().startsWith("/srv/data")) {
            throw new SecurityException("outside the root");
        }
        new FileInputStream(p.toFile()); // @vuln /srv/data-backup starts with the root
    }

    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String f = req.getParameter("f");
        Path p = Paths.get(f).normalize();
        if (!p.toString().startsWith("/srv/data/")) {
            throw new SecurityException("outside the root");
        }
        new FileInputStream(p.toFile()); // @safe root ends with a separator
    }

    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String f = req.getParameter("f");
        Path p = Paths.get(f).normalize();
        if (p.toString().startsWith("/srv/data/") == false) {
            throw new SecurityException("outside the root");
        }
        new FileInputStream(p.toFile()); // @safe reached only when the test is true
    }
}
