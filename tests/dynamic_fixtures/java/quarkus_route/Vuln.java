// Phase 14 — Quarkus reactive route, vulnerable.
//
// `@Path("/run")` on the type + `@GET` on the handler matches the
// Phase 14 [`JavaShape::detect`] for Quarkus.  The harness invokes
// `run(payload)` via reflection.

// import io.quarkus.runtime.Quarkus;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@Path("/run")
public class Vuln {
    @GET
    public String run(String payload) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        if (payload == null) payload = "";
        String[] cmd = {"/bin/sh", "-c", "echo hello " + payload};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            out.append(line);
            out.append('\n');
            System.out.println(line);
        }
        p.waitFor();
        return out.toString();
    }
}
