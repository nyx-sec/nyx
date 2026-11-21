import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeParseIntOnlyQuery extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String id = req.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + Integer.parseInt(id);
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:x");
             Statement st = c.createStatement()) {
            st.executeQuery(sql);
        }
    }
}
