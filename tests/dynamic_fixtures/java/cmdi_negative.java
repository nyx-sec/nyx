// Command injection — negative fixture.
// Safe: exec with args array; no shell; semicolons are inert.
// Entry: Entry.runPing(String)  Cap: CODE_EXEC
// Expected verdict: NotConfirmed

import java.io.*;

public class Entry {
    public static void runPing(String host) throws Exception {
        // Array form: each element is a literal argument — no shell expansion.
        String[] cmd = {"echo", "hello", host};
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        p.waitFor();
    }
}
