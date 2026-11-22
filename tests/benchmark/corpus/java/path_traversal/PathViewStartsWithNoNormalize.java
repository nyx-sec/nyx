import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathViewStartsWithNoNormalize extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String lang = req.getParameter("lang");
        File langsDir = new File("/srv/app", "langs");
        File langFile = new File(langsDir, lang);
        // toAbsolutePath() keeps `..` segments, so this guard proves nothing.
        if (!langFile.toPath().toAbsolutePath().startsWith(langsDir.toPath().toAbsolutePath())) {
            resp.sendError(400);
            return;
        }
        try (FileInputStream in = new FileInputStream(langFile)) {
            in.read();
        }
    }
}
