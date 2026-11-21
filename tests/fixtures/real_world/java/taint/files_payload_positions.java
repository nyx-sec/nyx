import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FilesPayloadPositions extends HttpServlet {
    private static final Path REPORT = Paths.get("/srv/reports/latest.txt");

    // Vulnerable: the request names the file.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        String text = Files.readString(Paths.get("/srv/reports", name));
        resp.setStatus(200);
    }

    // Safe: the request picks only the charset of a fixed file.
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cs = req.getParameter("charset");
        String text = Files.readString(REPORT, Charset.forName(cs));
        resp.setStatus(200);
    }

    // Safe: request text is written into a fixed file.
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String body = req.getParameter("body");
        Files.writeString(REPORT, body);
        resp.setStatus(204);
    }
}
