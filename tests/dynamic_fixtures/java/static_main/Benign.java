// Phase 14 — static `main(String[])` entry, benign.
//
// Discards `args[0]` and runs a fixed echo — payload never reaches the
// shell-interpreted slot so the cmdi marker cannot fire.

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Benign {
    public static void main(String[] args) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
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
