// File I/O — positive fixture.
// Vulnerable: reads file at user-controlled path without sanitization.
// Entry: Entry.readFile(String)  Cap: FILE_IO
// Expected verdict: Confirmed.
//
// The harness plants a canary file (`nyx_pt_canary`, whose CONTENT is the
// collision-resistant marker) at the workdir root and an empty `testfiles/`
// directory beside it. Reading `testfiles/ + userPath` without normalising is
// the traversal sink: the vuln payload `../nyx_pt_canary` escapes `testfiles/`
// back to the planted canary, so its marker content reaches stdout.

import java.io.*;
import java.nio.file.*;

public class Entry {
    public static void readFile(String userPath) throws Exception {
        // Base directory the harness plants the canary one level above.
        Path testfileDir = Paths.get(System.getProperty("user.dir"), "testfiles");
        // Vulnerable: no normalisation / containment check on `userPath`.
        Path filePath = testfileDir.resolve(userPath);
        System.out.print("__NYX_SINK_HIT__\n");
        try {
            String content = new String(Files.readAllBytes(filePath));
            System.out.print(content);
        } catch (IOException e) {
            // silent
        }
    }
}
