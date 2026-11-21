import java.io.*;
import java.sql.*;

public class SafeFactoryReturnsHandle {
    public static Connection connect(String url) throws SQLException {
        Connection c = DriverManager.getConnection(url);
        return c;
    }

    public static Reader reader(String p) throws IOException {
        return new BufferedReader(new FileReader(p));
    }
}
