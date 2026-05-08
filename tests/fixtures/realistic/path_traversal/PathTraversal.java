// Phase 13 path-traversal positive (Java).  Servlet reads
// `req.getParameter("name")` (Source) and feeds it through `Paths.get`
// into `Files.readAllBytes` (new FILE_IO sink rule in
// `src/labels/java.rs`).  `Paths.get` is a forwarder; default arg→return
// propagation smears the tainted `name` into the constructed Path, and
// the path arg of `Files.readAllBytes` carries the FILE_IO sink payload.
package handlers;

import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class PathTraversal {
    public byte[] handle(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        return Files.readAllBytes(Paths.get("/var/data", name));
    }
}
