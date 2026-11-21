import java.io.FileInputStream;
import java.sql.Connection;
import java.sql.DriverManager;

// A return in the try body (and in the catch handler) still runs the finally
// clause, which closes the resource.  Not a leak on any path.
class ReturnThroughFinally {
    int readFirst(String path) throws Exception {
        FileInputStream in = new FileInputStream(path);
        try {
            return in.read();
        } finally {
            in.close();
        }
    }

    int isolation(String url) throws Exception {
        Connection c = DriverManager.getConnection(url);
        try {
            return c.getTransactionIsolation();
        } catch (Exception e) {
            return -1;
        } finally {
            c.close();
        }
    }

    int partial(String path, boolean quick) throws Exception {
        FileInputStream in = new FileInputStream(path);
        try {
            if (quick) {
                return 0;
            }
            return in.read();
        } finally {
            in.close();
        }
    }
}
