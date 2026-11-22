import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathViewStartsWithNormalizeSafe extends HttpServlet {
    // The guard tests the normalized absolute view of the file against the
    // normalized absolute view of its directory.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String lang = req.getParameter("lang");
        File langsDir = new File("/srv/app", "langs");
        File langFile = new File(langsDir, lang);
        if (!langFile.toPath().normalize().toAbsolutePath()
                .startsWith(langsDir.toPath().normalize().toAbsolutePath())) {
            resp.sendError(400);
            return;
        }
        try (FileInputStream in = new FileInputStream(langFile)) {
            in.read();
        }
    }
}
