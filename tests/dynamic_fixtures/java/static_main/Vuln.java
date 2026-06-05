// Phase 14 — static `main(String[])` entry, vulnerable.
//
// Payload arrives as `args[0]` and lands in a shell-interpreted
// `Runtime.exec` invocation.

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Vuln {
    public static void main(String[] args) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        String input = args.length > 0 ? args[0] : "";
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
