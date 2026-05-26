// Micronaut `@Controller`, vulnerable.
//
// `@Controller("/run")` on the class + `@Get("/{id}")` on the handler
// matches `JavaShape::MicronautRoute`. The harness keeps the real
// Micronaut annotations on the classpath and replays the route through
// those annotations.

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@Controller("/run")
public class Vuln {
    @Get("/{id}")
    public String show(String id) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        if (id == null) id = "";
        String[] cmd = {"/bin/sh", "-c", "echo hello " + id};
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
