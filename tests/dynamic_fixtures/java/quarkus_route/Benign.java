// Quarkus reactive route, benign.

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@Path("/run")
public class Benign {
    @GET
    public String run(String payload) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        if (payload == null) payload = "";
        String[] cmd = {"/bin/sh", "-c", "echo hello"};
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
