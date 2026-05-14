// Phase 14 — plain static method, benign.
//
// Invokes a fixed shell command and discards the user input — the `;`
// in a vuln payload cannot escape because the payload is never passed
// to a shell-interpreted argv slot.

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Benign {
    public static void processInput(String input) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        // No-op echo of a fixed string — `input` is dropped.
        String[] cmd = {"/bin/sh", "-c", "echo hello"};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        p.waitFor();
    }
}
