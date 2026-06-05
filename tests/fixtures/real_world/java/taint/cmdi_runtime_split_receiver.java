import java.io.*;
import javax.servlet.http.*;

public class RuntimeSplitReceiverHandler extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String param = request.getHeader("vector");

        // Split-receiver Runtime.exec: the receiver is bound to a local in
        // one statement, then exec is called on it in another. The OWASP
        // Benchmark cmdi shape places the tainted data in the environment
        // array (arg 1), not the command (arg 0).
        Runtime r = Runtime.getRuntime();
        String[] args = { "/bin/sh", "-c", "echo nyx" };
        String[] argsEnv = { "TAINT=" + param };
        r.exec(args, argsEnv);
    }
}
