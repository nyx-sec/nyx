import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
import java.nio.file.*;
import java.util.Map;

@RestController
public class FileController {
    private static final Map<String, String> REPORTS = Map.of("daily", "/srv/daily.csv");

    @GetMapping("/delete")
    public void delete(@RequestParam String file) throws Exception {
        Path p = Paths.get(file);
        Files.delete(p);
    }

    @GetMapping("/download")
    public byte[] download(@RequestParam String file) throws Exception {
        Path p = Paths.get("/var/data", file);
        return Files.readAllBytes(p);
    }

    @GetMapping("/report")
    public byte[] report(@RequestParam String kind) throws Exception {
        String path = REPORTS.get(kind);
        return Files.readAllBytes(Paths.get(path));
    }
}

class LegacyServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("f");
        load(name);
    }

    private byte[] load(String fname) throws Exception {
        Path p = Paths.get("/var/data", fname);
        return Files.readAllBytes(p);
    }
}
