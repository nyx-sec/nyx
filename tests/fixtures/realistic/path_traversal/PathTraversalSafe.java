// Phase 13 path-traversal sanitized (Java).  Canonicalises the path
// via `base.resolve(name).normalize()` and validates containment with
// `startsWith(base)`; the canonical value is returned as a string,
// never reaching a FILE_IO sink.  Demonstrates the new `Path.normalize`
// Sanitizer(FILE_IO) recogniser registered in `src/labels/java.rs`.
package handlers;

import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class PathTraversalSafe {
    public String safeHandle(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        Path base = Paths.get("/var/data");
        Path candidate = base.resolve(name).normalize();
        if (!candidate.startsWith(base)) {
            throw new SecurityException("escape");
        }
        return candidate.toString();
    }
}
