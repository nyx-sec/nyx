import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqliExecuteStatementConcat {
    void lookup(Connection c, HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        Statement st = c.createStatement();
        st.execute("SELECT * FROM t WHERE n='" + name + "'");
    }
}
