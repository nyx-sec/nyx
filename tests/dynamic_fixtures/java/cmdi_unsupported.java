// Command injection — unsupported fixture.
// Entry is an instance method; test sets confidence = Low.
// Expected verdict: Unsupported

import java.io.*;

public class Entry {
    public void execute(String cmd) throws Exception {
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    }
}
