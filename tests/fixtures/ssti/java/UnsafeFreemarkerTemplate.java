// Unsafe: Apache Velocity `Velocity.evaluate(ctx, out, "tag", src)` parses
// `src` as an inline template and renders it in one call.  When `src` is
// taken from a request parameter, this is direct SSTI.  Static-method
// shape ensures the chain text is `Velocity.evaluate`, matching the
// class-qualified Java SSTI rule without needing receiver type inference.

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;

public class UnsafeFreemarkerTemplate {
    public String render(HttpServletRequest req) throws Exception {
        String src = req.getParameter("template");
        VelocityContext ctx = new VelocityContext();
        StringWriter out = new StringWriter();
        Velocity.evaluate(ctx, out, "user-template", src);
        return out.toString();
    }
}
