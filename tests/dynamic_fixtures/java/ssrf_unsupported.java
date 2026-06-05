// SSRF — unsupported fixture.
// Entry is an instance method; test sets confidence = Low.
// Expected verdict: Unsupported

import java.io.*;
import java.net.*;

public class Entry {
    public void fetch(String url) throws Exception {
        new URL(url).openStream().close();
    }
}
