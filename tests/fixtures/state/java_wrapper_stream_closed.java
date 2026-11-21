import java.io.*;
import java.util.zip.*;

// The wrapper owns the stream it wraps; closing (or returning, or
// try-with-resources on) the wrapper closes the inner stream.
// Expected: no resource findings.
public class JavaWrapperStreamClosed {
    public static int wrapClose(String p) throws IOException {
        FileInputStream in = new FileInputStream(p);
        BufferedInputStream b = new BufferedInputStream(in);
        int x = b.read();
        b.close();
        return x;
    }

    public static int gzFinally(String p) throws IOException {
        FileInputStream in = new FileInputStream(p);
        GZIPInputStream gz = new GZIPInputStream(in);
        try {
            gz.read();
        } finally {
            gz.close();
        }
        return 0;
    }

    public static void twrWrap(String p) throws IOException {
        FileInputStream in = new FileInputStream(p);
        try (BufferedInputStream b = new BufferedInputStream(in)) {
            b.read();
        }
    }

    public static String nested(String p) throws IOException {
        FileInputStream in = new FileInputStream(p);
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        String line = br.readLine();
        br.close();
        return line;
    }

    public static void dataOut(String p) throws IOException {
        FileOutputStream fos = new FileOutputStream(p);
        DataOutputStream dos = new DataOutputStream(fos);
        dos.writeInt(1);
        dos.close();
    }
}
