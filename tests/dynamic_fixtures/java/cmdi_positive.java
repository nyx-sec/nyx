// Command injection — positive fixture.
// Vulnerable: passes user input to /bin/sh -c via Runtime.exec.
// Entry: Entry.runPing(String)  Cap: CODE_EXEC
// Expected verdict: Confirmed ("; echo NYX_PWN_CMDI" echoes the marker)

import java.io.*;

public class Entry {
    public static void runPing(String host) throws Exception {
        System.out.print("__NYX_SINK_HIT__\n");
        String[] cmd = {"/bin/sh", "-c", "echo hello " + host};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        p.waitFor();
    }
}
