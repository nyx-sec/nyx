// Spring `@RestController`, vulnerable.

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/run")
public class Vuln {
    @Autowired
    private CommandRunner runner;

    @GetMapping
    public String run(@RequestParam("payload") String payload) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        CommandRunner r = (runner != null) ? runner : new CommandRunner();
        String out = r.run("echo hello " + payload);
        System.out.print(out);
        return out;
    }
}
