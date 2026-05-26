// Quarkus reactive route, vulnerable. The harness keeps the real
// Jakarta REST annotations on the classpath and replays the route
// through those annotations.

import io.quarkus.runtime.Quarkus;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

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
