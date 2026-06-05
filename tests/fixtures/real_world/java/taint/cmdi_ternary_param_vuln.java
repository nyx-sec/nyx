import java.io.*;
import javax.servlet.http.*;

// Constant-condition ternary, VULNERABLE polarity. `(500/42) + num` is
// `11 + 196 = 207 > 200` (integer division) — ALWAYS true — and the TRUE arm
// selects the tainted `param`, so the reachable arm carries taint and only the
// `: "..."` const arm is dead. The fold must prune the dead const arm while
// keeping the live `param`, so the cmdi finding at `r.exec` MUST still fire.
public class TernaryParamVuln extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String param = request.getHeader("vector");

        int num = 196;
        String bar = (500 / 42) + num > 200 ? param : "This_should_never_happen";

        String cmd = "echo ";
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(cmd + bar);
    }
}
