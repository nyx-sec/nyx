// Phase 14 — Spring `@RestController`, vulnerable.
//
// Controller declares an `@Autowired CommandRunner` field so the
// Phase 09 Java import-extractor sees the Spring annotation surface.
// The harness instantiates the controller via reflection and invokes
// `run(payload)`; the field stays null at runtime (no Spring DI), so
// the handler constructs the helper on demand.

@RestController
@RequestMapping("/run")
public class Vuln {
    @Autowired
    private CommandRunner runner;

    public String run(String payload) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        CommandRunner r = (runner != null) ? runner : new CommandRunner();
        String out = r.run("echo hello " + payload);
        System.out.print(out);
        return out;
    }
}
