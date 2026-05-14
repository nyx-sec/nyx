// Phase 14 — plain static method, vulnerable.
//
// JDK-only.  Passes user input through `/bin/sh -c` so a `;` in the
// payload escapes into a new command (CMDI oracle marker fires).

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Vuln {
    public static void processInput(String input) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        String[] cmd = {"/bin/sh", "-c", "echo hello " + input};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        p.waitFor();
    }
}
