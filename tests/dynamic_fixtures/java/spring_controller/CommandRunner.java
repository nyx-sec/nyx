// Phase 14 fixture stub — Spring-injected helper service.
// The fixture's controller declares `@Autowired CommandRunner runner;`
// so the harness exercises the Phase 09 import-extraction path
// (`@Autowired` is the marker that flags `org.springframework` as a
// transitive dep).  At runtime the harness instantiates the controller
// via reflection's default ctor — the @Autowired field stays null
// because there is no Spring container; the controller's handler
// guards against null and constructs a fresh CommandRunner on demand.

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class CommandRunner {
    public String run(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", cmd});
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            out.append(line);
            out.append('\n');
        }
        p.waitFor();
        return out.toString();
    }
}
