import java.io.*;

// A local declared before it is assigned is still a local.
// Expected: state-resource-leak.
public class JavaLocalDeclaredLate {
    public int first(String p) throws IOException {
        FileInputStream in;
        in = new FileInputStream(p);
        return in.read();
    }
}
