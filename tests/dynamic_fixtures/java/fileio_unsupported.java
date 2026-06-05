// File I/O — unsupported fixture.
// Entry is an instance method; test sets confidence = Low.
// Expected verdict: Unsupported

import java.io.*;
import java.nio.file.*;

public class Entry {
    public void serve(String path) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(path));
        System.out.write(data);
    }
}
