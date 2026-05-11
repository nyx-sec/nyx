// Safe: Velocity.evaluate receives a constant template source string.
// The user-controlled value is bound as a context *variable* (data),
// which Velocity renders via its escape policy — not as template source.

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;

public class SafeFreemarkerConstant {
    public String render(HttpServletRequest req) throws Exception {
        VelocityContext ctx = new VelocityContext();
        ctx.put("name", req.getParameter("name"));
        StringWriter out = new StringWriter();
        Velocity.evaluate(ctx, out, "greeting", "Hello, $name");
        return out.toString();
    }
}
