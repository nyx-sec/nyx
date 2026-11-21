import java.io.*;
import java.util.*;

// The streams are handed to collections owned by the caller.
// Expected: no resource findings.
public class JavaContainerAdd {
    public static void collect(String p, List<InputStream> out) throws IOException {
        FileInputStream s = new FileInputStream(p);
        out.add(s);
    }

    public static void index(String p, Map<String, InputStream> byPath) throws IOException {
        FileInputStream s = new FileInputStream(p);
        byPath.put(p, s);
    }
}
