import java.io.*;
import java.net.*;
import java.sql.*;

// Each method hands the resource to its caller.  Expected: no resource
// findings.
public class JavaFactoryReturnsHandle {
    public static Connection connect(String url) throws SQLException {
        Connection c = DriverManager.getConnection(url);
        return c;
    }

    public static Socket dial(String h, int p) throws IOException {
        Socket s = new Socket(h, p);
        s.setSoTimeout(5000);
        return s;
    }

    public static Reader reader(String p) throws IOException {
        return new BufferedReader(new FileReader(p));
    }

    public static InputStream buffered(String p) throws IOException {
        FileInputStream fis = new FileInputStream(p);
        return new BufferedInputStream(fis);
    }
}
