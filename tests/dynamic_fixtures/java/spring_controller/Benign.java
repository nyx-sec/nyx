// Phase 14 — Spring `@RestController`, benign.
//
// Same shape as the vuln but the controller runs a fixed echo and
// drops `payload`.

@RestController
@RequestMapping("/run")
public class Benign {
    @Autowired
    private CommandRunner runner;

    public String run(String payload) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        CommandRunner r = (runner != null) ? runner : new CommandRunner();
        String out = r.run("echo hello");
        System.out.print(out);
        return out;
    }
}
