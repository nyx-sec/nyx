// Phase 19 (Track M.1) — class-method benign control for Java.
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class Benign {
    public static class UserRepository {
        public UserRepository() {}

        public void findByName(String name) throws SQLException {
            Connection c = DriverManager.getConnection("jdbc:sqlite::memory:");
            PreparedStatement ps = c.prepareStatement("SELECT id FROM users WHERE name = ?");
            ps.setString(1, name);
            ps.execute();
            ps.close();
            c.close();
        }
    }
}
