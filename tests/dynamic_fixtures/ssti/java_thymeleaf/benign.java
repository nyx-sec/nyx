// Phase 04 (Track J.2) — Java Thymeleaf benign control fixture.
//
// Renders a fixed template that interpolates the body as a model
// variable; the user-controlled value never reaches the template
// compiler.
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

public class Benign {
    public static String run(String body) {
        TemplateEngine engine = new TemplateEngine();
        Context ctx = new Context();
        ctx.setVariable("safeBody", body);
        return engine.process("[[${safeBody}]]", ctx);
    }
}
