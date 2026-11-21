import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SqliParseIntConcatName extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String id = req.getParameter("id");
        String name = req.getParameter("name");
        String sql = "SELECT * FROM users WHERE id = " + Integer.parseInt(id) + " AND name = '" + name + "'";
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:x");
             Statement st = c.createStatement()) {
            st.executeQuery(sql);
        }
    }
}
