// Spring-injected helper service used by the controller fixtures.

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
