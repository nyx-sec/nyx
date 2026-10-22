import java.sql.*;
import javax.servlet.http.*;

public class SqliPreparedStatementConcat extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("password");
        String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + param + "'";
        Connection connection = DriverManager.getConnection("jdbc:h2:mem:test");
        PreparedStatement statement =
                connection.prepareStatement(sql, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
        statement.setString(1, "foo");
        statement.execute();
    }
}
