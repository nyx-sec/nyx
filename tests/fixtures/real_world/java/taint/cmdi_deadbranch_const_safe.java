import java.io.*;
import javax.servlet.http.*;

// Dead-branch constant condition (OWASP Benchmark cmdi non-vulnerable shape).
// The guard `(7*42) - num > 200` is `294 - 86 = 208 > 200`, i.e. ALWAYS true,
// so `bar` is provably the constant string and the tainted `else` arm
// (`bar = param`) is unreachable. The constant-branch fold
// (`fold_constant_branches`) must prune the dead edge and drop the tainted
// phi operand so `r.exec(cmd + bar)` carries no attacker data — NO finding.
public class DeadBranchConstSafe extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String param = request.getHeader("vector");

        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) {
            bar = "This_should_always_happen";
        } else {
            bar = param;
        }

        String cmd = "echo ";
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(cmd + bar);
    }
}
