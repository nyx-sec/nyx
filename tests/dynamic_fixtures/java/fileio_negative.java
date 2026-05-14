// File I/O — negative fixture.
// Safe: normalizes path and checks it stays within the base directory.
// Entry: Entry.readFile(String)  Cap: FILE_IO
// Expected verdict: NotConfirmed

import java.io.*;
import java.nio.file.*;

public class Entry {
    // `/tmp` exists on Linux and macOS so `toRealPath()` resolves cleanly on
    // both. The traversal payload still escapes the base (which is the point
    // of the safe-path check) so the verdict stays NotConfirmed.
    private static final String BASE_DIR = "/tmp";

    public static void readFile(String userPath) throws Exception {
        Path base = Paths.get(BASE_DIR).toRealPath();
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
