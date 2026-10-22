import java.io.*;

// Pre-try-with-resources idiom: the handle starts null and is closed in
// finally only when it was opened.  Expected: no resource findings.
public class JavaFinallyNullGuard {
    public void readOne(String p) throws IOException {
        FileInputStream in = null;
        try {
            in = new FileInputStream(p);
            in.read();
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
}
