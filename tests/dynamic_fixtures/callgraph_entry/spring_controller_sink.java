// Phase 04 fixture: Spring controller method calls a helper that holds
// the sink. The callgraph-aware spec-derivation path must rewrite the
// harness entry to the controller method `runCommand`, not the helper
// `execHelper`.

package fixture;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SinkController {
    private void execHelper(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd); // sink: command injection
    }

    @PostMapping("/run")
    public String runCommand(@RequestBody String cmd) throws Exception {
        execHelper(cmd);
        return "ok";
    }
}
