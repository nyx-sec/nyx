import java.io.*;
import javax.servlet.http.*;

// Constant-condition ternary (OWASP Benchmark cmdi non-vulnerable shape).
// `(7*18) + num` is `126 + 106 = 232 > 200` — ALWAYS true — so `bar` is the
// constant string and the `: param` arm is statically dead. Routing the Java
// ternary through the branch+phi diamond lets `fold_constant_branches` prune
// the dead tainted arm exactly as it does for the if-form — NO finding.
public class TernaryConstSafe extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String param = request.getHeader("vector");

        int num = 106;
        String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;

        String cmd = "echo ";
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(cmd + bar);
    }
}
