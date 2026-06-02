// File I/O — negative fixture.
// Safe: normalizes the path and checks it stays within the base directory, so
// the traversal payload cannot escape `testfiles/` to reach the planted canary.
// Entry: Entry.readFile(String)  Cap: FILE_IO
// Expected verdict: NotConfirmed

import java.io.*;
import java.nio.file.*;

public class Entry {
    public static void readFile(String userPath) throws Exception {
        // Same base the harness plants the canary one level above; the
        // containment check is what makes this safe.
        Path base = Paths.get(System.getProperty("user.dir"), "testfiles").toRealPath();
        Path resolved = base.resolve(userPath).normalize();
        if (!resolved.startsWith(base)) {
            System.out.println("Access denied");
            return;
        }
        try {
            byte[] data = Files.readAllBytes(resolved);
            int len = Math.min(data.length, 100);
            System.out.write(data, 0, len);
        } catch (IOException e) {
            System.out.println("File not found");
        }
    }
}
