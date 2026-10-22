import javax.servlet.http.*;
import java.sql.*;

public class ReportServlet extends HttpServlet {
    private Connection conn;

    protected void split(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = '" + name + "'");
        ResultSet rs = ps.executeQuery();
        rs.close();
    }

    protected void owaspShape(HttpServletRequest request) throws Exception {
        String param = request.getParameter("p");
        String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + param + "'";
        PreparedStatement statement =
                conn.prepareStatement(sql, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
        statement.setString(1, "foo");
        statement.execute();
    }

    protected void tryWithResources(HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        try (PreparedStatement ps = conn.prepareStatement("DELETE FROM t WHERE id = " + id)) {
            ps.executeUpdate();
        }
    }

    protected void parameterised(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ResultSet rs = ps.executeQuery();
        rs.close();
        ps.execute();
    }
}
