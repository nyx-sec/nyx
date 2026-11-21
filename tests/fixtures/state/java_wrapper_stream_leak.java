import java.io.*;

// Neither the wrapper nor the stream it wraps is closed.
// Expected: a resource leak finding.
public class JavaWrapperStreamLeak {
    public static int leak(String p) throws IOException {
        FileInputStream in = new FileInputStream(p);
        BufferedInputStream b = new BufferedInputStream(in);
        return b.read();
    }
}
