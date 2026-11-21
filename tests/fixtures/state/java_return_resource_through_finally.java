import java.io.FileInputStream;
import java.io.InputStream;

// Ownership goes to the caller through the return even though a finally
// clause (that does not touch the stream) runs first.
class ReturnResourceThroughFinally {
    InputStream open(String path) throws Exception {
        InputStream in = new FileInputStream(path);
        try {
            in.read();
            return in;
        } finally {
            System.out.println("audit");
        }
    }
}
