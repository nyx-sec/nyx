// File I/O — positive fixture.
// Vulnerable: reads file at user-controlled path without sanitization.
// Entry: Entry.readFile(String)  Cap: FILE_IO
// Expected verdict: Confirmed (../../../../etc/passwd → "root:" in output)

import java.io.*;
import java.nio.file.*;

public class Entry {
    public static void readFile(String userPath) throws Exception {
        Path filePath = Paths.get("/var/data", userPath);
        System.out.print("__NYX_SINK_HIT__\n");
        try {
            String content = new String(Files.readAllBytes(filePath));
            System.out.print(content);
        } catch (IOException e) {
            // silent
        }
    }
}
