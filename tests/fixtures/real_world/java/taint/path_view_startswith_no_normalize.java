import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathViewStartsWithNoNormalize extends HttpServlet {
    // toAbsolutePath() does not remove `..`, so the guard proves nothing.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String lang = req.getParameter("lang");
        File langsDir = new File("/srv/app", "langs");
        File langFile = new File(langsDir, lang);
        if (!langFile.toPath().toAbsolutePath()
                .startsWith(langsDir.toPath().toAbsolutePath())) {
            resp.sendError(400);
            return;
        }
        try (FileInputStream in = new FileInputStream(langFile)) {
            in.read();
        }
    }
}
