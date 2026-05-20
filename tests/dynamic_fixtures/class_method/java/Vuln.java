// Phase 19 (Track M.1) — class-method vuln fixture for Java.
//
// UserRepository.findByName concatenates user input into a JDBC SQL
// statement.  Default constructor exists so the harness can build the
// receiver without stubbing dependencies.
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.SQLException;

public class Vuln {
    public static class UserRepository {
        public UserRepository() {}

        public void findByName(String name) throws SQLException {
            Connection c = DriverManager.getConnection("jdbc:sqlite::memory:");
            Statement s = c.createStatement();
            // SINK: tainted concat into SQL
            String sql = "SELECT id FROM users WHERE name = '" + name + "'";
            s.execute(sql);
            s.close();
            c.close();
        }
    }
}
