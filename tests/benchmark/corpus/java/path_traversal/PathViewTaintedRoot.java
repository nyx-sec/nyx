import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathViewTaintedRoot extends HttpServlet {
    // The root the file is compared against comes from the request too, so
    // passing the guard confines nothing.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("n");
        String root = req.getParameter("r");
        File f = new File(name);
        if (!f.toPath().normalize().startsWith(root)) {
            return;
        }
        try (FileInputStream in = new FileInputStream(f)) {
            in.read();
        }
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("n");
        File f = new File(name);
        if (!f.toPath().normalize().startsWith(req.getParameter("r"))) {
            return;
        }
        try (FileInputStream in = new FileInputStream(f)) {
            in.read();
        }
    }
}
