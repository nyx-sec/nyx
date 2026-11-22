import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathViewConstantRoot extends HttpServlet {
    // The root is a constant directory, so the normalized view confines the file.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("n");
        File dir = new File("/srv/data");
        File f = new File(dir, name);
        if (!f.toPath().normalize().startsWith(dir.toPath().normalize())) {
            return;
        }
        try (FileInputStream in = new FileInputStream(f)) {
            in.read();
        }
    }
}
