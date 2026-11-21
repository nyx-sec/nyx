import java.io.*;
import java.net.*;
import java.sql.*;

// Resources stored in fields belong to the object (or class) and are
// released by its close().  Expected: no resource findings.
public class JavaFieldStore implements Closeable {
    private static Connection shared;
    private final Socket socket;
    private FileInputStream in;

    public static void init(String url) throws SQLException {
        shared = DriverManager.getConnection(url);
    }

    public JavaFieldStore(String host, int port, String p) throws IOException {
        this.socket = new Socket(host, port);
        in = new FileInputStream(p);
    }

    @Override
    public void close() throws IOException {
        in.close();
        socket.close();
    }
}
