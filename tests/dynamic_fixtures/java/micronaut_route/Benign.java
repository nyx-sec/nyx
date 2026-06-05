// Micronaut `@Controller`, benign.
//
// Same shape as the vuln but echoes a constant string instead of
// concatenating the path variable into a shell command.

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@Controller("/run")
public class Benign {
    @Get("/{id}")
    public String show(String id) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
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
