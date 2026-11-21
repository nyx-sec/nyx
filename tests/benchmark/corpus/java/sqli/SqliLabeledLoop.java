import javax.servlet.http.*;
import java.sql.*;

public class SqliLabeledLoop extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String[] ids = req.getParameterValues("id");
        Statement st = conn.createStatement();
        outer:
        for (String id : ids) {
            st.executeUpdate("DELETE FROM t WHERE id = '" + id + "'");
        }
    }
}
