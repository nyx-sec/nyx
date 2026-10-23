import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class RuntimeExecLiteral {
    public void restart(String reason) throws IOException {
        Runtime.getRuntime().exec("systemctl restart app");
    }

    public void run(HttpServletRequest req) throws IOException {
        String cmd = req.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }

    public void runSplit(HttpServletRequest req) throws IOException {
        String cmd = req.getParameter("cmd");
        Runtime rt = Runtime.getRuntime();
        rt.exec(cmd);
    }
}
