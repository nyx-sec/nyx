import java.nio.file.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class PathsGetSpringTraversal {
    @GetMapping("/download")
    public byte[] download(@RequestParam String file) throws Exception {
        Path p = Paths.get("/var/data", file);
        return Files.readAllBytes(p);
    }
}
