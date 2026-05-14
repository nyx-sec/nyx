// Command injection — negative fixture.
// Safe: exec with args array; no shell; injected metacharacters are inert.
// Entry: Entry.runPing(String)  Cap: CODE_EXEC
// Expected verdict: NotConfirmed
//
// `id` ignores extra positional args (treats them as usernames it can't find
// and writes the "no such user" error to stderr, not stdout). Switching from
// `echo` keeps the array-exec demonstration intact while ensuring the
// vuln-payload marker can never leak into the stdout stream the oracle reads.

import java.io.*;

public class Entry {
    public static void runPing(String host) throws Exception {
        // Sink-reachability probe: we did reach the exec call site.
        System.out.print("__NYX_SINK_HIT__\n");
        // Array form: each element is a literal argument — no shell expansion.
        String[] cmd = {"id", host};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        p.waitFor();
    }
}
