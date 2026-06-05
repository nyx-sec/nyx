import java.io.*;
import javax.servlet.http.*;

// Dead-branch constant condition, VULNERABLE polarity (OWASP Benchmark cmdi
// vulnerable shape). The guard `(500/42) + num > 200` is `11 + 196 = 207 > 200`
// using integer division — ALWAYS true — and the TRUE arm assigns the tainted
// `param`. So the live branch carries taint and the `else bar = "never"` arm is
// dead. The constant-branch fold must prune the DEAD (else) edge and keep the
// reachable tainted `bar = param`, so `r.exec(cmd + bar)` MUST still fire. This
// is the zero-false-negative guard: the fold must never prune the live arm.
public class DeadBranchParamVuln extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String param = request.getHeader("vector");

        String bar;
        int num = 196;
        if ((500 / 42) + num > 200) {
            bar = param;
        } else {
            bar = "This_should_never_happen";
        }

        String cmd = "echo ";
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(cmd + bar);
    }
}
