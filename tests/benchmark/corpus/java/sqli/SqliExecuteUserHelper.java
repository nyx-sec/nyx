import java.sql.Connection;
import javax.servlet.http.HttpServletRequest;

public class ExecuteUserHelper {
    static Connection c;

    static class Db {
        static void execute(String s) throws Exception {
            c.createStatement().execute(s);
        }
    }

    static void execute(String s) throws Exception {
        c.createStatement().execute(s);
    }

    void run(HttpServletRequest req) throws Exception {
        String n = req.getParameter("n");
        Db.execute("select * from t where a='" + n + "'");
        execute("delete from t where a='" + n + "'");
    }
}
