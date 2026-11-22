import java.sql.Connection;
import java.sql.Statement;

public class ExecuteConcatJdbc {
    void lookup(Connection c, String name) throws Exception {
        Statement st = c.createStatement();
        st.execute("SELECT * FROM t WHERE n='" + name + "'");
    }
}
