import java.io.*;
import org.xml.sax.InputSource;

// InputSource does not own or close the stream; the stream is closed
// directly.  Expected: no resource findings.
public class JavaNonCloseableCtor {
    public static void parse(String p) throws IOException {
        FileInputStream in = new FileInputStream(p);
        InputSource src = new InputSource(in);
        handle(src);
        in.close();
    }

    static void handle(InputSource s) {}
}
