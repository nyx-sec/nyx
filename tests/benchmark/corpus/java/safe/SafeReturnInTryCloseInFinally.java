import java.io.FileInputStream;
import java.sql.Connection;
import java.sql.DriverManager;

// Returns inside try (and catch) run the finally clause, which closes the
// resource.  Nothing leaks on any path.
public class SafeReturnInTryCloseInFinally {
    public int firstByte(String path) throws Exception {
        FileInputStream in = new FileInputStream(path);
        try {
            return in.read();
        } finally {
            in.close();
        }
    }

    public int isolation(String url) throws Exception {
        Connection c = DriverManager.getConnection(url);
        try {
            return c.getTransactionIsolation();
        } catch (Exception e) {
            return -1;
        } finally {
            c.close();
        }
    }
}
